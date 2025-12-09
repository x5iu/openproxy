//! HTTP/2 client connection management for upstream connections.
//!
//! This module provides a connection pool for HTTP/2 upstream connections,
//! allowing multiplexed requests over a single connection.

use std::collections::HashMap;
use std::future::poll_fn;
use std::sync::Arc;

use bytes::Bytes;
use h2::client::SendRequest;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::client::TlsStream;

use crate::Error;

/// Lazily initialized TLS client config with HTTP/2 ALPN support.
static TLS_H2_CLIENT_CONFIG: std::sync::LazyLock<Arc<rustls::ClientConfig>> =
    std::sync::LazyLock::new(|| {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        // Prefer HTTP/2, fallback to HTTP/1.1
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    });

/// Creates a new TLS connector with HTTP/2 ALPN support.
#[inline]
pub fn new_h2_tls_connector() -> tokio_rustls::TlsConnector {
    tokio_rustls::TlsConnector::from(Arc::clone(&*TLS_H2_CLIENT_CONFIG))
}

/// HTTP/2 connection handle that can be cloned and shared.
#[derive(Clone)]
pub struct H2Connection {
    send_request: SendRequest<Bytes>,
    endpoint: Arc<str>,
}

impl H2Connection {
    /// Creates a new H2Connection from an existing SendRequest handle.
    pub fn new(send_request: SendRequest<Bytes>, endpoint: &str) -> Self {
        Self {
            send_request,
            endpoint: Arc::from(endpoint),
        }
    }

    /// Returns the endpoint this connection is for.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns a clone of the SendRequest handle.
    pub fn send_request(&self) -> SendRequest<Bytes> {
        self.send_request.clone()
    }

    /// Checks if the connection is still ready to send requests.
    /// This attempts a non-blocking poll_ready check.
    pub async fn ready(&mut self) -> bool {
        let mut send_request = self.send_request.clone();
        poll_fn(|cx| send_request.poll_ready(cx))
            .await
            .is_ok()
    }
}

/// Pool for HTTP/2 client connections.
///
/// HTTP/2 allows multiplexing, so we can reuse a single connection
/// for multiple concurrent requests to the same endpoint.
pub struct H2Pool {
    connections: RwLock<HashMap<String, H2Connection>>,
}

impl Default for H2Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl H2Pool {
    /// Creates a new empty H2 connection pool.
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Gets an existing HTTP/2 connection for the given endpoint, if available and ready.
    pub async fn get(&self, endpoint: &str) -> Option<H2Connection> {
        let conn = {
            let connections = self.connections.read().await;
            connections.get(endpoint).cloned()
        };

        if let Some(mut conn) = conn {
            if conn.ready().await {
                return Some(conn);
            } else {
                // Connection is not ready, remove it from the pool
                self.remove(endpoint).await;
            }
        }
        None
    }

    /// Stores an HTTP/2 connection in the pool.
    pub async fn insert(&self, endpoint: &str, conn: H2Connection) {
        let mut connections = self.connections.write().await;
        connections.insert(endpoint.to_string(), conn);
    }

    /// Removes a connection from the pool (e.g., when it's no longer usable).
    pub async fn remove(&self, endpoint: &str) {
        let mut connections = self.connections.write().await;
        connections.remove(endpoint);
    }
}

/// Establishes a new HTTP/2 connection to the upstream server.
///
/// This function performs TLS handshake with ALPN negotiation and
/// establishes an HTTP/2 connection.
pub async fn connect_h2(
    endpoint: &str,
    sock_address: &str,
    use_tls: bool,
) -> Result<H2Connection, Error> {
    let stream = TcpStream::connect(sock_address).await?;

    if use_tls {
        let connector = new_h2_tls_connector();
        let server_name: rustls_pki_types::ServerName<'static> = endpoint
            .to_string()
            .try_into()
            .map_err(|_| Error::InvalidServerName(endpoint.to_string()))?;
        let tls_stream = connector.connect(server_name, stream).await?;

        // Check ALPN negotiation result
        let alpn = tls_stream.get_ref().1.alpn_protocol();
        if !matches!(alpn, Some(b"h2")) {
            // Server doesn't support HTTP/2, this is an error for our use case
            return Err(Error::IO(std::io::Error::other(
                "upstream server does not support HTTP/2",
            )));
        }

        connect_h2_over_stream(tls_stream, endpoint).await
    } else {
        // For non-TLS, we use HTTP/2 with prior knowledge (h2c)
        connect_h2_over_stream(stream, endpoint).await
    }
}

/// Establishes HTTP/2 connection over any AsyncRead+AsyncWrite stream.
async fn connect_h2_over_stream<S>(stream: S, endpoint: &str) -> Result<H2Connection, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = h2::client::handshake(stream)
        .await
        .map_err(|e| Error::H2(e))?;

    // Spawn a task to drive the connection
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::warn!(error = e.to_string(); "h2_client_connection_error");
        }
    });

    Ok(H2Connection::new(send_request, endpoint))
}

/// Wrapper for TLS stream that implements the necessary traits.
pub type H2TlsStream = TlsStream<TcpStream>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2_pool_new() {
        let pool = H2Pool::new();
        // Just verify it can be created
        assert!(pool.connections.try_read().is_ok());
    }

    #[test]
    fn test_h2_pool_default() {
        let pool = H2Pool::default();
        assert!(pool.connections.try_read().is_ok());
    }

    #[tokio::test]
    async fn test_h2_pool_get_nonexistent() {
        let pool = H2Pool::new();
        let result = pool.get("nonexistent.example.com").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_h2_pool_remove_nonexistent() {
        let pool = H2Pool::new();
        // Should not panic
        pool.remove("nonexistent.example.com").await;
    }

    #[test]
    fn test_new_h2_tls_connector() {
        // Verify the connector can be created
        let _connector = new_h2_tls_connector();
    }

    #[test]
    fn test_tls_h2_client_config() {
        // Verify the lazy static config is correctly initialized with h2 ALPN
        let config = &*TLS_H2_CLIENT_CONFIG;
        assert!(config.alpn_protocols.contains(&b"h2".to_vec()));
        assert!(config.alpn_protocols.contains(&b"http/1.1".to_vec()));
        // h2 should be preferred (first in the list)
        assert_eq!(config.alpn_protocols[0], b"h2".to_vec());
    }

    #[test]
    fn test_h2_connection_endpoint() {
        // We can't easily create a real H2Connection without a real connection,
        // but we can test the endpoint storage/retrieval logic indirectly
        // by checking the Arc<str> behavior
        let endpoint = Arc::<str>::from("api.example.com");
        assert_eq!(&*endpoint, "api.example.com");
    }

    #[tokio::test]
    async fn test_h2_pool_multiple_endpoints() {
        let pool = H2Pool::new();

        // Try to get from multiple non-existent endpoints
        assert!(pool.get("endpoint1.example.com").await.is_none());
        assert!(pool.get("endpoint2.example.com").await.is_none());
        assert!(pool.get("endpoint3.example.com").await.is_none());
    }

    #[tokio::test]
    async fn test_h2_pool_remove_multiple_endpoints() {
        let pool = H2Pool::new();

        // Should not panic when removing non-existent endpoints
        pool.remove("endpoint1.example.com").await;
        pool.remove("endpoint2.example.com").await;

        // Pool should still be empty
        let connections = pool.connections.read().await;
        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn test_connect_h2_invalid_address() {
        // Test that connect_h2 returns an error for invalid addresses
        let result = connect_h2("example.com", "256.256.256.256:443", true).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_h2_connection_refused() {
        // Test that connect_h2 returns an error when connection is refused
        // Using localhost with an unlikely port
        let result = connect_h2("localhost", "127.0.0.1:1", false).await;
        assert!(result.is_err());
    }
}
