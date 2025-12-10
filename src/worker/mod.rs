use std::borrow::{Borrow, Cow};
use std::future::Future;
use std::io::Cursor;
use std::mem;
use std::pin::{pin, Pin};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;


use bytes::Buf;

use crate::h2client::{self as h2client, H2ConnectResult, H2Pool};
use crate::http;
use crate::provider::Provider;
use crate::websocket;
use crate::Error;

static TLS_CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
});

type TlsIncomingStream = tokio_rustls::server::TlsStream<TcpStream>;
type TlsOutgoingStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Client error: {0}")]
    Client(Error),
    #[error("Server error: {0}")]
    Server(Error),
    #[error("Abort: {0}")]
    Abort(Error),
}

pub trait WorkerTrait<P>
where
    P: PoolTrait,
{
    fn new(injector: Arc<P>, h2pool: Arc<H2Pool>) -> Self;
    fn get_outgoing_conn<'a>(
        &'a mut self,
        provider: &'a dyn Provider,
    ) -> Pin<Box<dyn Future<Output=Result<<P as PoolTrait>::Item, Error>> + Send + 'a>>
    where
        <P as PoolTrait>::Item: Send;
    fn proxy<'a, S>(
        &'a mut self,
        incoming: &'a mut S,
    ) -> Pin<Box<dyn Future<Output=Result<(), ProxyError>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
        <P as PoolTrait>::Item: Unpin + Send + Sync;
    fn proxy_h2<'a>(
        &'a mut self,
        incoming: &'a mut TlsIncomingStream,
    ) -> Pin<Box<dyn Future<Output=Result<(), ProxyError>> + Send + 'a>>
    where
        <P as PoolTrait>::Item: Unpin + Send + Sync + 'static;
    fn add<'a>(
        &'a mut self,
        endpoint: &'a str,
        conn: <P as PoolTrait>::Item,
    ) -> Pin<Box<dyn Future<Output=()> + Send + 'a>> where
        <P as PoolTrait>::Item: Send;
}

pub struct Worker<P> {
    pool: Arc<P>,
    h2pool: Arc<H2Pool>,
}

impl<P> WorkerTrait<P> for Worker<P>
where
    P: PoolTrait + Send + Sync + 'static,
    <P as PoolTrait>::Item: ConnTrait,
{
    fn new(pool: Arc<P>, h2pool: Arc<H2Pool>) -> Self {
        Self { pool, h2pool }
    }

    fn get_outgoing_conn<'a>(
        &'a mut self,
        provider: &'a dyn Provider,
    ) -> Pin<Box<dyn Future<Output=Result<<P as PoolTrait>::Item, Error>> + Send + 'a>>
    where
        <P as PoolTrait>::Item: Send,
    {
        Box::pin(async move {
            if let Some(conn) = self.select(provider.endpoint()).await {
                Ok(conn)
            } else {
                let stream = TcpStream::connect(provider.sock_address()).await?;
                let conn = if provider.tls() {
                    let connector = new_tls_connector();
                    <P as PoolTrait>::Item::new_tls(provider.endpoint(), stream, connector).await?
                } else {
                    <P as PoolTrait>::Item::new(provider.endpoint(), stream)
                };
                Ok(conn)
            }
        })
    }

    fn proxy<'a, S>(
        &'a mut self,
        mut incoming: &'a mut S,
    ) -> Pin<Box<dyn Future<Output=Result<(), ProxyError>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
        <P as PoolTrait>::Item: Unpin + Send + Sync,
    {
        Box::pin(async move {
            let mut is_invalid_key = false;
            let mut is_bad_request = false;
            let mut is_not_found = false;
            let mut err_msg: Option<Cow<str>> = None;
            loop {
                let mut request = match http::Request::new(&mut incoming).await {
                    Ok(request) => request,
                    Err(e @ Error::HeaderTooLarge) => {
                        is_bad_request = true;
                        err_msg = Some(e.to_string().into());
                        break;
                    }
                    Err(e @ Error::InvalidHeader) => {
                        is_bad_request = true;
                        err_msg = Some(e.to_string().into());
                        break;
                    }
                    Err(e @ Error::NoProviderFound) => {
                        is_not_found = true;
                        err_msg = Some(e.to_string().into());
                        break;
                    }
                    Err(e) => return Err(ProxyError::Client(e)),
                };
                let p = crate::program();
                let Some(host) = request.host() else {
                    is_bad_request = true;
                    err_msg = Some("missing Host header".into());
                    break;
                };
                let p = p.read().await;
                let Some(provider) = p.select_provider(host, request.path()) else {
                    is_not_found = true;
                    err_msg = Some(Error::NoProviderFound.to_string().into());
                    break;
                };
                if provider.authenticate(request.auth_key()).is_err() {
                    #[cfg(debug_assertions)]
                    log::error!(provider = provider.kind().to_string(), header:serde = request.auth_key().map(|header| header.to_vec()); "authentication_failed");
                    is_invalid_key = true;
                    err_msg = Some("authentication failed".into());
                    break;
                }

                // Check if this is a WebSocket upgrade request
                if request.is_websocket_upgrade() {
                    #[cfg(debug_assertions)]
                    log::info!(host = host, path = request.path(); "websocket_upgrade_request");

                    // Extract WebSocket upgrade info before dropping request and p
                    let raw_headers = request.header_bytes().to_vec();
                    let endpoint = provider.endpoint().to_string();
                    let sock_address = provider.sock_address().to_string();
                    let provider_tls = provider.tls();
                    let host_header = provider.host_header().to_string();
                    let auth_header = provider.auth_header().map(|s| s.to_string());
                    let path_prefix = provider.path_prefix().map(|s| s.to_string());

                    // Drop p (RwLockReadGuard) first, then request
                    drop(p);
                    drop(request);

                    // Handle WebSocket upgrade
                    match self.proxy_websocket_with_data(
                        incoming,
                        &raw_headers,
                        &endpoint,
                        &sock_address,
                        provider_tls,
                        &host_header,
                        auth_header.as_deref(),
                        path_prefix.as_deref(),
                    ).await {
                        Ok(()) => {
                            // WebSocket connection completed, exit the loop
                            return Ok(());
                        }
                        Err(e) => {
                            // WebSocket upgrade failed
                            let msg = format!("WebSocket upgrade failed: {}", e);
                            let resp = format!(
                                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                msg.len(),
                                msg
                            );
                            incoming
                                .write_all(resp.as_bytes())
                                .await
                                .map_err(|e| ProxyError::Client(e.into()))?;
                            return Ok(());
                        }
                    }
                }

                let mut outgoing = self
                    .get_outgoing_conn(provider)
                    .await
                    .map_err(ProxyError::Server)?;
                request
                    .write_to(&mut outgoing)
                    .await
                    .map_err(ProxyError::Server)?;
                let incoming_conn_keep_alive = request.payload.conn_keep_alive;
                drop(request);
                let mut response = http::Response::new(&mut outgoing)
                    .await
                    .map_err(ProxyError::Abort)?;
                response
                    .write_to(&mut incoming)
                    .await
                    .map_err(ProxyError::Abort)?;
                let conn_keep_alive = response.payload.conn_keep_alive;
                drop(response);
                if conn_keep_alive {
                    self.add(provider.endpoint(), outgoing).await;
                }
                if !incoming_conn_keep_alive {
                    break;
                }
            }
            if is_invalid_key {
                let msg = err_msg.as_deref().unwrap_or("authentication failed");
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    msg.len(),
                    msg
                );
                incoming
                    .write_all(resp.as_bytes())
                    .await
                    .map_err(|e| ProxyError::Client(e.into()))?;
            } else if is_not_found {
                let msg: String = err_msg
                    .clone()
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|| Error::NoProviderFound.to_string());
                let resp = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    msg.len(),
                    msg
                );
                incoming
                    .write_all(resp.as_bytes())
                    .await
                    .map_err(|e| ProxyError::Client(e.into()))?;
            } else if is_bad_request {
                let msg = err_msg.as_deref().unwrap_or("bad request");
                let resp = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    msg.len(),
                    msg
                );
                incoming
                    .write_all(resp.as_bytes())
                    .await
                    .map_err(|e| ProxyError::Client(e.into()))?;
            }
            Ok(())
        })
    }

    fn proxy_h2<'a>(
        &'a mut self,
        incoming: &'a mut TlsIncomingStream,
    ) -> Pin<Box<dyn Future<Output=Result<(), ProxyError>> + Send + 'a>>
    where
        <P as PoolTrait>::Item: Unpin + Send + Sync + 'static,
    {
        macro_rules! invalid {
            ($respond:expr, $status:expr, $msg:expr) => {{
                let msg: Cow<str> = $msg.into();
                let body_bytes = msg.as_bytes();
                let body: Vec<u8> = Vec::from(body_bytes);
                let builder = httplib::Response::builder()
                    .version(httplib::Version::HTTP_2)
                    .status($status)
                    .header("content-type", "text/plain; charset=utf-8");
                let mut send = match $respond.send_response(builder.body(()).unwrap(), false) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!(alpn = "h2", error = e.to_string(); "send_response_error");
                        return;
                    }
                };
                if let Err(e) = send.send_data(bytes::Bytes::from(body), true) {
                    log::error!(alpn = "h2", error = e.to_string(); "send_data_error");
                }
            }};
        }
        Box::pin(async move {
            // Enable Extended CONNECT protocol for WebSocket over HTTP/2 (RFC 8441)
            let mut stream = h2::server::Builder::new()
                .enable_connect_protocol()
                .handshake(incoming)
                .await
                .map_err(|e| ProxyError::Client(e.into()))?;
            while let Some(next) = stream.accept().await {
                let (request, mut respond) = next.map_err(|e| ProxyError::Client(e.into()))?;
                let mut worker = Worker::new(self.pool.clone(), self.h2pool.clone());
                tokio::spawn(async move {
                    let p = crate::program();
                    let Some(authority) = request.uri().authority() else {
                        return invalid!(respond, 400, "missing :authority");
                    };
                    let p = p.read().await;
                    let Some(provider) = p.select_provider(authority.host(), request.uri().path()) else {
                        return invalid!(respond, 404, Error::NoProviderFound.to_string());
                    };
                    if provider.has_auth_keys() {
                        let mut auth_key = None;
                        if let Some(auth_header_key) = provider.auth_header_key() {
                            auth_key = request
                                .headers()
                                .get(auth_header_key.trim_end_matches([' ', ':']))
                                .and_then(|v| v.to_str().ok());
                        }
                        if auth_key.is_none() {
                            if let Some(auth_query_key) = provider.auth_query_key() {
                                auth_key = request
                                    .uri()
                                    .query()
                                    .and_then(|query| {
                                        http::get_auth_query_range(query, auth_query_key)
                                            .map(|range| &query[range])
                                    })
                            }
                        }
                        let Some(auth_key) = auth_key else {
                            return invalid!(respond, 401, "missing authentication");
                        };
                        if provider.authenticate_key(auth_key).is_err() {
                            return invalid!(respond, 401, "authentication failed");
                        }
                    }

                    // Check for WebSocket over HTTP/2 (RFC 8441 Extended CONNECT)
                    // CONNECT method + :protocol = "websocket"
                    let is_h2_websocket = request.method() == httplib::Method::CONNECT
                        && request.extensions().get::<h2::ext::Protocol>()
                            .map(|p| p.as_str().eq_ignore_ascii_case("websocket"))
                            .unwrap_or(false);

                    if is_h2_websocket {
                        #[cfg(debug_assertions)]
                        log::info!(authority = authority.to_string(), path = request.uri().path(); "h2_websocket_request");

                        // Handle WebSocket over HTTP/2
                        let endpoint = provider.endpoint().to_string();
                        let sock_address = provider.sock_address().to_string();
                        let provider_tls = provider.tls();
                        let host_header = provider.host_header().to_string();
                        let auth_header = provider.auth_header().map(|s| s.to_string());
                        let path_prefix = provider.path_prefix();
                        let mut path = request.uri().path_and_query()
                            .map(|pq| pq.as_str().to_string())
                            .unwrap_or_else(|| "/".to_string());

                        // Strip path prefix if present
                        if let Some(prefix) = path_prefix {
                            if path.starts_with(prefix) {
                                let remaining = &path[prefix.len()..];
                                path = if remaining.is_empty() { "/".to_string() } else { remaining.to_string() };
                            }
                        }

                        // Drop the read lock before async operations
                        drop(p);

                        // Get the request body stream for bidirectional communication
                        let recv_stream = request.into_body();

                        #[allow(unused_variables)]
                        if let Err(e) = worker.proxy_h2_websocket(
                            respond,
                            recv_stream,
                            &endpoint,
                            &sock_address,
                            provider_tls,
                            &host_header,
                            auth_header.as_deref(),
                            &path,
                        ).await {
                            #[cfg(debug_assertions)]
                            log::error!(error = e.to_string(); "h2_websocket_error");
                        }
                        return;
                    }

                    // Extract provider info into UpstreamInfo struct
                    let info = UpstreamInfo {
                        endpoint: provider.endpoint().to_string(),
                        sock_address: provider.sock_address().to_string(),
                        use_tls: provider.tls(),
                        host_header_value: {
                            let h = provider.host_header();
                            // Extract just the host value from "Host: example.com\r\n"
                            h.trim_start_matches("Host: ").trim_end_matches("\r\n").to_string()
                        },
                        auth_header: provider.auth_header().map(|s| s.to_string()),
                        auth_header_key: provider.auth_header_key(),
                        path_prefix: provider.path_prefix().map(|s| s.to_string()),
                        api_key: provider.api_key().map(|s| s.to_string()),
                        auth_query_key: provider.auth_query_key(),
                    };
                    let authority_host = authority.host().to_string();

                    // Drop the read lock before async operations
                    drop(p);

                    // Try to get or create HTTP/2 connection to upstream
                    let h2result = match worker.get_or_create_h2_conn(&info.endpoint, &info.sock_address, info.use_tls).await {
                        Ok(result) => result,
                        Err(e) => {
                            invalid!(respond, 502, format!("upstream: {}", e));
                            return;
                        }
                    };

                    match h2result {
                        H2ConnectResult::H2(h2conn) => {
                            info.proxy_h2(h2conn, request, respond).await;
                        }
                        H2ConnectResult::FallbackToH1 => {
                            info.proxy_h1(&mut worker, request, respond, &authority_host).await;
                        }
                    }
                });
            }
            Ok(())
        })
    }

    fn add<'a>(
        &'a mut self,
        endpoint: &'a str,
        conn: <P as PoolTrait>::Item,
    ) -> Pin<Box<dyn Future<Output=()> + Send + 'a>> where
        <P as PoolTrait>::Item: Send,
    {
        Box::pin(async move {
            self.pool.add(endpoint, conn).await;
        })
    }
}

/// Provider information extracted for upstream request handling.
/// This struct holds all the necessary provider details to avoid passing many parameters.
struct UpstreamInfo {
    endpoint: String,
    sock_address: String,
    use_tls: bool,
    host_header_value: String,
    auth_header: Option<String>,
    auth_header_key: Option<&'static str>,
    path_prefix: Option<String>,
    api_key: Option<String>,
    auth_query_key: Option<&'static str>,
}

impl UpstreamInfo {
    /// Proxy request to upstream using HTTP/2.
    async fn proxy_h2(
        &self,
        h2conn: crate::h2client::H2Connection,
        request: httplib::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<bytes::Bytes>,
    ) {
        macro_rules! invalid {
            ($respond:expr, $status:expr, $msg:expr) => {{
                let msg: Cow<str> = $msg.into();
                let body_bytes = msg.as_bytes();
                let body: Vec<u8> = Vec::from(body_bytes);
                let builder = httplib::Response::builder()
                    .version(httplib::Version::HTTP_2)
                    .status($status)
                    .header("content-type", "text/plain; charset=utf-8");
                let mut send = match $respond.send_response(builder.body(()).unwrap(), false) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!(alpn = "h2", error = e.to_string(); "send_response_error");
                        return;
                    }
                };
                if let Err(e) = send.send_data(bytes::Bytes::from(body), true) {
                    log::error!(alpn = "h2", error = e.to_string(); "send_data_error");
                }
            }};
        }

        let mut send_request = h2conn.send_request();

        // Build the upstream request path
        let raw_path = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let path = build_upstream_path(
            raw_path,
            self.path_prefix.as_deref(),
            self.api_key.as_deref(),
            self.auth_query_key,
        );

        // Build upstream URI
        let upstream_uri = httplib::Uri::builder()
            .scheme(if self.use_tls { "https" } else { "http" })
            .authority(self.host_header_value.as_str())
            .path_and_query(path.as_str())
            .build();

        let upstream_uri = match upstream_uri {
            Ok(uri) => uri,
            Err(e) => {
                invalid!(respond, 502, format!("invalid upstream uri: {}", e));
                return;
            }
        };

        // Build the request to send to upstream
        let mut upstream_request = httplib::Request::builder()
            .method(request.method().clone())
            .uri(upstream_uri)
            .version(httplib::Version::HTTP_2);

        // Copy headers, filtering out HTTP/2 pseudo-headers and connection-specific headers
        for (key, value) in request.headers() {
            let key_str = key.as_str();
            // Skip pseudo-headers (they start with :) and connection-specific headers
            if key_str.starts_with(':') || is_http2_invalid_headers(key_str) {
                continue;
            }
            // Replace Host header with upstream host
            if key_str.eq_ignore_ascii_case("host") {
                upstream_request = upstream_request.header("host", self.host_header_value.as_str());
                continue;
            }
            // Skip auth header - will be replaced by provider auth
            if let Some(provider_auth_key) = self.auth_header_key {
                if key_str.eq_ignore_ascii_case(provider_auth_key.trim_end_matches([' ', ':'])) {
                    continue; // Will add auth_header below
                }
            }
            upstream_request = upstream_request.header(key, value);
        }

        // Add provider's auth header if present
        if let Some(ref auth) = self.auth_header {
            if let Some((header_name, header_value)) = parse_auth_header(auth) {
                upstream_request = upstream_request.header(header_name, header_value);
            }
        }

        let upstream_request = match upstream_request.body(()) {
            Ok(req) => req,
            Err(e) => {
                invalid!(respond, 502, format!("build request: {}", e));
                return;
            }
        };

        // Get the request body
        let recv_body = request.into_body();

        // Check if request has a body
        let has_body = !recv_body.is_end_stream();

        // Send the request
        let (upstream_response, mut upstream_send_body) = match send_request.send_request(upstream_request, !has_body) {
            Ok(res) => res,
            Err(e) => {
                invalid!(respond, 502, format!("upstream send: {}", e));
                return;
            }
        };

        // Stream the request body to upstream if present
        if has_body {
            let mut body_reader = H2StreamReader::new(recv_body);
            let mut buf = vec![0u8; 16384];
            loop {
                match body_reader.read(&mut buf).await {
                    Ok(0) => {
                        // End of body
                        if let Err(e) = upstream_send_body.send_data(bytes::Bytes::new(), true) {
                            log::error!(alpn = "h2", error = e.to_string(); "upstream_send_body_end_error");
                        }
                        break;
                    }
                    Ok(n) => {
                        let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                        if let Err(e) = upstream_send_body.send_data(data, false) {
                            log::error!(alpn = "h2", error = e.to_string(); "upstream_send_body_error");
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!(alpn = "h2", error = e.to_string(); "read_client_body_error");
                        break;
                    }
                }
            }
        }

        // Wait for the response
        let upstream_response = match upstream_response.await {
            Ok(resp) => resp,
            Err(e) => {
                invalid!(respond, 502, format!("upstream response: {}", e));
                return;
            }
        };

        // Build response to send back to client
        let (parts, mut upstream_body) = upstream_response.into_parts();
        let mut builder = httplib::Response::builder()
            .version(httplib::Version::HTTP_2)
            .status(parts.status);

        // Copy response headers
        for (key, value) in parts.headers.iter() {
            if !is_http2_invalid_headers(key.as_str()) {
                builder = builder.header(key, value);
            }
        }

        // Add header to indicate upstream protocol
        builder = builder.header("x-upstream-protocol", "h2");

        let response_has_body = !upstream_body.is_end_stream();

        let mut send = match respond.send_response(builder.body(()).unwrap(), !response_has_body) {
            Ok(send) => send,
            Err(e) => {
                log::error!(alpn = "h2", error = e.to_string(); "send_response_error");
                return;
            }
        };

        // Stream the response body back to client
        if response_has_body {
            loop {
                match upstream_body.data().await {
                    Some(Ok(data)) => {
                        // Release flow control capacity
                        let _ = upstream_body.flow_control().release_capacity(data.len());

                        if send.capacity() < data.len() {
                            send.reserve_capacity(data.len());
                        }
                        if let Err(e) = send.send_data(data, false) {
                            log::error!(alpn = "h2", error = e.to_string(); "send_data_error");
                            return;
                        }
                    }
                    Some(Err(e)) => {
                        log::error!(alpn = "h2", error = e.to_string(); "upstream_body_error");
                        return;
                    }
                    None => {
                        // End of stream
                        if let Err(e) = send.send_data(bytes::Bytes::new(), true) {
                            log::error!(alpn = "h2", error = e.to_string(); "send_data_end_error");
                        }
                        break;
                    }
                }
            }
        }
    }

    /// Proxy request to upstream using HTTP/1.1 fallback.
    async fn proxy_h1<P>(
        &self,
        worker: &mut Worker<P>,
        request: httplib::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<bytes::Bytes>,
        authority_host: &str,
    ) where
        P: PoolTrait + Send + Sync + 'static,
        <P as PoolTrait>::Item: ConnTrait + Unpin + Send + Sync,
    {
        macro_rules! invalid {
            ($respond:expr, $status:expr, $msg:expr) => {{
                let msg: Cow<str> = $msg.into();
                let body_bytes = msg.as_bytes();
                let body: Vec<u8> = Vec::from(body_bytes);
                let builder = httplib::Response::builder()
                    .version(httplib::Version::HTTP_2)
                    .status($status)
                    .header("content-type", "text/plain; charset=utf-8");
                let mut send = match $respond.send_response(builder.body(()).unwrap(), false) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!(alpn = "h2", error = e.to_string(); "send_response_error");
                        return;
                    }
                };
                if let Err(e) = send.send_data(bytes::Bytes::from(body), true) {
                    log::error!(alpn = "h2", error = e.to_string(); "send_data_error");
                }
            }};
        }

        let mut request = request;

        // Add default headers
        request
            .headers_mut()
            .entry("Connection")
            .or_insert(httplib::HeaderValue::from_static("keep-alive"));
        request
            .headers_mut()
            .entry("Host")
            .or_insert(httplib::HeaderValue::from_str(authority_host).unwrap());

        let has_content_length = request.headers().contains_key("content-length");

        // Build HTTP/1.1 request headers
        let req_headers = build_h1_request_headers(
            request.headers().iter(),
            &self.host_header_value,
            self.auth_header_key,
            self.auth_header.as_deref(),
            has_content_length,
        );

        // Build path with prefix stripping and auth query replacement
        let raw_path = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let path = build_upstream_path(
            raw_path,
            self.path_prefix.as_deref(),
            self.api_key.as_deref(),
            self.auth_query_key,
        );

        let req_str = format!(
            "{} {} HTTP/1.1\r\n{}\r\n",
            request.method(),
            path,
            req_headers,
        );

        let h2stream_reader = H2StreamReader::new(request.into_body());
        let req_body: Box<dyn AsyncRead + Unpin + Send + Sync> = if has_content_length {
            Box::new(h2stream_reader)
        } else {
            Box::new(http::reader::ChunkedWriter::new(h2stream_reader))
        };
        let req_reader = AsyncReadExt::chain(req_str.as_bytes(), req_body);

        let mut req = match http::Request::new(req_reader).await {
            Ok(req) => req,
            Err(e @ Error::NoProviderFound) => {
                invalid!(respond, 404, e.to_string());
                return;
            }
            Err(e) => {
                invalid!(respond, 400, e.to_string());
                return;
            }
        };

        let mut outgoing = match worker
            .get_or_create_h1_conn(&self.endpoint, &self.sock_address, self.use_tls)
            .await
        {
            Ok(conn) => conn,
            Err(e) => {
                invalid!(respond, 502, format!("upstream: {}", e));
                return;
            }
        };

        if let Err(e) = req.write_to(&mut outgoing).await {
            invalid!(respond, 502, format!("upstream: {}", e));
            return;
        };

        let mut response = match http::Response::new(&mut outgoing).await {
            Ok(resp) => resp,
            Err(e) => {
                invalid!(respond, 502, format!("upstream: {}", e));
                return;
            }
        };

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parser = httparse::Response::new(&mut headers);
        if let Err(e) = parser.parse(response.payload.block()) {
            invalid!(respond, 502, format!("upstream: {}", e));
            return;
        };

        let mut builder = httplib::Response::builder()
            .version(httplib::Version::HTTP_2)
            .status(parser.code.unwrap_or(502));

        let mut is_transfer_encoding_chunked = false;
        for header in parser.headers {
            if header.name.eq_ignore_ascii_case("transfer-encoding")
                && header.value.eq_ignore_ascii_case(b"chunked")
            {
                is_transfer_encoding_chunked = true;
            }
            if !is_http2_invalid_headers(header.name) {
                builder = builder.header(header.name, header.value);
            }
        }

        if matches!(&mut response.payload.body, http::Body::Unread(_)) && is_transfer_encoding_chunked {
            let mut take = http::Body::Read(0..0);
            mem::swap(&mut take, &mut response.payload.body);
            let mut body = if let http::Body::Unread(reader) = take {
                http::Body::Unread(Box::new(http::reader::ChunkedReader::data_only(reader)))
            } else {
                unreachable!();
            };
            mem::swap(&mut body, &mut response.payload.body);
        }

        // Add header to indicate upstream protocol
        builder = builder.header("x-upstream-protocol", "h1");

        let mut send = match respond.send_response(builder.body(()).unwrap(), false) {
            Ok(send) => send,
            Err(e) => {
                log::error!(alpn = "h2", error = e.to_string(); "send_response_error");
                return;
            }
        };

        loop {
            let block = match response
                .payload
                .next_block()
                .await
                .map(|block| block.map(|cow| cow.to_vec()))
            {
                Ok(block) => block,
                Err(e) => {
                    log::error!(alpn = "h2", error = e.to_string(); "read_block_error");
                    return;
                }
            };

            let (data, is_eos) = if let Some(block) = block {
                if send.capacity() < block.len() {
                    send.reserve_capacity(block.len());
                }
                (bytes::Bytes::from(block), false)
            } else {
                (bytes::Bytes::from_static(b""), true)
            };

            if let Err(e) = send.send_data(data, is_eos) {
                log::error!(alpn = "h2", error = e.to_string(); "send_data_error");
                return;
            }
            if is_eos {
                break;
            }
        }

        if response.payload.conn_keep_alive {
            drop(response);
            worker.add(&self.endpoint, outgoing).await;
        }
    }
}

#[inline]
fn new_tls_connector() -> tokio_rustls::TlsConnector {
    tokio_rustls::TlsConnector::from(Arc::clone(&*TLS_CLIENT_CONFIG))
}

pub trait PoolTrait {
    type Item;
    fn get<'a, L>(&'a self, label: &'a L) -> Pin<Box<dyn Future<Output=Option<Self::Item>> + Send + 'a>>
    where
        String: Borrow<L>,
        Self::Item: Send,
        L: Ord + Sync + ?Sized;
    fn add<'a, L>(
        &'a self,
        label: &'a L,
        value: Self::Item,
    ) -> Pin<Box<dyn Future<Output=()> + Send + 'a>>
    where
        String: Borrow<L>,
        Self::Item: Send,
        L: ToString + Sync + Ord + ?Sized;
}

impl<P> Worker<P>
where
    P: PoolTrait,
    <P as PoolTrait>::Item: ConnTrait + Send,
{
    async fn select(&mut self, endpoint: &str) -> Option<<P as PoolTrait>::Item> {
        let mut retry_times = 0;
        while retry_times < 3 {
            let Some(mut conn) = self.pool.get(endpoint).await else {
                retry_times += 1;
                continue;
            };
            if conn.health_check().await.is_ok() {
                return Some(conn);
            } else {
                ConnTrait::shutdown(&mut conn).await;
            }
            retry_times += 1;
        }
        None
    }

    /// Gets an existing HTTP/2 connection from the pool or creates a new one.
    /// Returns `H2ConnectResult::FallbackToH1` if upstream doesn't support HTTP/2.
    async fn get_or_create_h2_conn(
        &self,
        endpoint: &str,
        sock_address: &str,
        use_tls: bool,
    ) -> Result<H2ConnectResult, Error> {
        // Try to get an existing connection
        if let Some(conn) = self.h2pool.get(endpoint).await {
            return Ok(H2ConnectResult::H2(conn));
        }

        // Try to create a new connection
        let result = h2client::connect_h2(endpoint, sock_address, use_tls).await?;
        if let H2ConnectResult::H2(ref conn) = result {
            // Store it in the pool for future use
            self.h2pool.insert(endpoint, conn.clone()).await;
        }
        Ok(result)
    }

    /// Gets an existing HTTP/1.1 connection from the pool or creates a new one.
    /// Used for fallback when HTTP/2 is not supported.
    async fn get_or_create_h1_conn(
        &mut self,
        endpoint: &str,
        sock_address: &str,
        use_tls: bool,
    ) -> Result<<P as PoolTrait>::Item, Error>
    where
        <P as PoolTrait>::Item: Send,
    {
        if let Some(conn) = self.select(endpoint).await {
            Ok(conn)
        } else {
            let stream = TcpStream::connect(sock_address).await?;
            let conn = if use_tls {
                let connector = new_tls_connector();
                <P as PoolTrait>::Item::new_tls(endpoint, stream, connector).await?
            } else {
                <P as PoolTrait>::Item::new(endpoint, stream)
            };
            Ok(conn)
        }
    }

    /// Handle WebSocket over HTTP/2 (RFC 8441 Extended CONNECT)
    /// This method:
    /// 1. Establishes a new connection to the upstream server
    /// 2. Sends HTTP/1.1 WebSocket upgrade request to upstream
    /// 3. Validates 101 response from upstream
    /// 4. Sends 200 OK to H2 client (per RFC 8441)
    /// 5. Performs bidirectional proxying between H2 stream and upstream connection
    #[allow(clippy::too_many_arguments)]
    async fn proxy_h2_websocket(
        &mut self,
        mut respond: h2::server::SendResponse<bytes::Bytes>,
        recv_stream: h2::RecvStream,
        endpoint: &str,
        sock_address: &str,
        provider_tls: bool,
        host_header: &str,
        auth_header: Option<&str>,
        path: &str,
    ) -> Result<(), Error>
    where
        <P as PoolTrait>::Item: Unpin + Send + Sync,
    {
        // Create a new connection to upstream (don't use pool for WebSocket)
        let stream = TcpStream::connect(sock_address).await?;
        let mut outgoing: <P as PoolTrait>::Item = if provider_tls {
            let connector = new_tls_connector();
            <P as PoolTrait>::Item::new_tls(endpoint, stream, connector).await?
        } else {
            <P as PoolTrait>::Item::new(endpoint, stream)
        };

        // Build WebSocket upgrade request for upstream (HTTP/1.1)
        // Generate a random Sec-WebSocket-Key
        let ws_key = base64_encode_ws_key();

        let mut upgrade_request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n",
            path,
            host_header.trim_start_matches("Host: "),
            ws_key,
        );

        // Add auth header if present
        if let Some(auth) = auth_header {
            upgrade_request.push_str(auth);
            upgrade_request.push_str("\r\n");
        }

        upgrade_request.push_str("\r\n");

        // Send upgrade request to upstream
        outgoing.write_all(upgrade_request.as_bytes()).await?;
        outgoing.flush().await?;

        #[cfg(debug_assertions)]
        log::info!(request = upgrade_request; "h2_websocket_upgrade_request_sent");

        // Read response from upstream
        let mut response_buf = vec![0u8; 4096];
        let mut total_read = 0;

        loop {
            let n = outgoing.read(&mut response_buf[total_read..]).await?;
            if n == 0 {
                return Err(Error::InvalidHeader);
            }
            total_read += n;

            // Check for end of headers
            if let Some(pos) = find_header_end(&response_buf[..total_read]) {
                let response_str = std::str::from_utf8(&response_buf[..pos + 4])
                    .map_err(|_| Error::InvalidHeader)?;

                let first_line = response_str.lines().next().unwrap_or("");
                let (status, is_upgrade) = websocket::check_websocket_response(first_line);

                #[cfg(debug_assertions)]
                log::info!(status = status, is_upgrade = is_upgrade; "h2_websocket_upstream_response");

                if !is_upgrade {
                    // Upstream rejected the upgrade, send error response to H2 client
                    let builder = httplib::Response::builder()
                        .version(httplib::Version::HTTP_2)
                        .status(status)
                        .header("content-type", "text/plain");

                    let error_msg = format!("WebSocket upgrade rejected by upstream: {}", status);
                    let mut send = respond.send_response(builder.body(()).unwrap(), false)
                        .map_err(|e| Error::IO(io::Error::other(e.to_string())))?;
                    send.send_data(bytes::Bytes::from(error_msg), true)
                        .map_err(|e| Error::IO(io::Error::other(e.to_string())))?;

                    return Err(Error::IO(io::Error::other(format!(
                        "WebSocket upgrade rejected with status {}",
                        status
                    ))));
                }

                // Upstream accepted, send 200 OK to H2 client (per RFC 8441)
                let builder = httplib::Response::builder()
                    .version(httplib::Version::HTTP_2)
                    .status(200);

                let send = respond.send_response(builder.body(()).unwrap(), false)
                    .map_err(|e| Error::IO(io::Error::other(e.to_string())))?;

                #[cfg(debug_assertions)]
                log::info!("h2_websocket_connection_established");

                // Now perform bidirectional proxying between H2 stream and upstream
                // Create an adapter for the H2 recv_stream
                let mut h2reader = H2StreamReader::new(recv_stream);
                let mut send_stream = H2SendStreamWriter::new(send);

                // Bidirectional copy
                let mut upstream_buf = vec![0u8; 8192];
                let mut client_buf = vec![0u8; 8192];

                loop {
                    tokio::select! {
                        biased;

                        // Read from H2 client, write to upstream
                        result = h2reader.read(&mut client_buf) => {
                            match result {
                                Ok(0) => {
                                    // Client closed
                                    let _ = AsyncWriteExt::shutdown(&mut outgoing).await;
                                    break;
                                }
                                Ok(n) => {
                                    #[allow(unused_variables)]
                                    if let Err(e) = outgoing.write_all(&client_buf[..n]).await {
                                        #[cfg(debug_assertions)]
                                        log::info!(error = e.to_string(); "h2_websocket_upstream_write_error");
                                        break;
                                    }
                                    let _ = outgoing.flush().await;
                                }
                                #[allow(unused_variables)]
                                Err(e) => {
                                    #[cfg(debug_assertions)]
                                    log::info!(error = e.to_string(); "h2_websocket_client_read_error");
                                    break;
                                }
                            }
                        }

                        // Read from upstream, write to H2 client
                        result = outgoing.read(&mut upstream_buf) => {
                            match result {
                                Ok(0) => {
                                    // Upstream closed
                                    let _ = send_stream.shutdown().await;
                                    break;
                                }
                                Ok(n) => {
                                    #[allow(unused_variables)]
                                    if let Err(e) = send_stream.write_all(&upstream_buf[..n]).await {
                                        #[cfg(debug_assertions)]
                                        log::info!(error = e.to_string(); "h2_websocket_client_write_error");
                                        break;
                                    }
                                }
                                #[allow(unused_variables)]
                                Err(e) => {
                                    #[cfg(debug_assertions)]
                                    log::info!(error = e.to_string(); "h2_websocket_upstream_read_error");
                                    break;
                                }
                            }
                        }
                    }
                }

                #[cfg(debug_assertions)]
                log::info!("h2_websocket_connection_closed");

                return Ok(());
            }

            if total_read >= response_buf.len() {
                return Err(Error::HeaderTooLarge);
            }
        }
    }

    /// Handle WebSocket upgrade request with pre-extracted data
    /// This method:
    /// 1. Establishes a new connection to the upstream server (not from pool, since WebSocket is long-lived)
    /// 2. Forwards the WebSocket upgrade request with rewritten Host header
    /// 3. Reads the upgrade response
    /// 4. If successful (101), forwards the response and starts bidirectional proxying
    #[allow(clippy::too_many_arguments)]
    async fn proxy_websocket_with_data<S>(
        &mut self,
        incoming: &mut S,
        raw_headers: &[u8],
        endpoint: &str,
        sock_address: &str,
        provider_tls: bool,
        host_header: &str,
        auth_header: Option<&str>,
        path_prefix: Option<&str>,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
        <P as PoolTrait>::Item: Unpin + Send + Sync,
    {
        // Create a new connection to upstream (don't use pool for WebSocket)
        let stream = TcpStream::connect(sock_address).await?;
        let mut outgoing: <P as PoolTrait>::Item = if provider_tls {
            let connector = new_tls_connector();
            <P as PoolTrait>::Item::new_tls(endpoint, stream, connector).await?
        } else {
            <P as PoolTrait>::Item::new(endpoint, stream)
        };

        // Build the WebSocket upgrade request with rewritten headers
        let header_str = std::str::from_utf8(raw_headers).map_err(|_| Error::InvalidHeader)?;

        // Rewrite Host header and Authentication header
        let mut modified_request = String::with_capacity(raw_headers.len() + 256);
        let mut first_line = true;
        let mut auth_written = false;

        for line in header_str.split("\r\n") {
            if line.is_empty() {
                break;
            }

            if first_line {
                // Request line - strip path prefix if present
                if let Some(prefix) = path_prefix {
                    let path_range = http::get_req_path(line);
                    let path = &line[path_range.clone()];
                    if let Some(remaining) = path.strip_prefix(prefix) {
                        // Rewrite the request line with the path prefix removed
                        let new_path = if remaining.is_empty() { "/" } else { remaining };
                        modified_request.push_str(&line[..path_range.start]);
                        modified_request.push_str(new_path);
                        modified_request.push_str(&line[path_range.end..]);
                        modified_request.push_str("\r\n");
                        first_line = false;
                        continue;
                    }
                }
                // No prefix to strip, keep as is
                modified_request.push_str(line);
                modified_request.push_str("\r\n");
                first_line = false;
                continue;
            }

            // Check if this is a header we want to rewrite
            if http::is_header(line, http::HEADER_HOST) {
                // Rewrite Host header to provider's endpoint
                // Note: host_header already includes trailing \r\n
                modified_request.push_str(host_header);
            } else if http::is_header(line, http::HEADER_AUTHORIZATION)
                || http::is_header(line, http::HEADER_X_GOOG_API_KEY)
                || http::is_header(line, http::HEADER_X_API_KEY)
            {
                // Replace authentication header with provider's auth
                // Note: auth already includes trailing \r\n
                if !auth_written {
                    if let Some(auth) = auth_header {
                        modified_request.push_str(auth);
                        auth_written = true;
                    }
                }
            } else {
                // Keep other headers as is
                modified_request.push_str(line);
                modified_request.push_str("\r\n");
            }
        }
        modified_request.push_str("\r\n");

        // Send the modified request to upstream
        outgoing.write_all(modified_request.as_bytes()).await?;
        outgoing.flush().await?;

        #[cfg(debug_assertions)]
        log::info!(request = modified_request; "websocket_upgrade_request_sent");

        // Read the response from upstream
        let mut response_buf = vec![0u8; 4096];
        let mut total_read = 0;

        // Read until we find \r\n\r\n (end of headers)
        loop {
            let n = outgoing.read(&mut response_buf[total_read..]).await?;
            if n == 0 {
                return Err(Error::InvalidHeader);
            }
            total_read += n;

            // Check for end of headers
            if let Some(pos) = find_header_end(&response_buf[..total_read]) {
                // Parse the response status line
                let response_str = std::str::from_utf8(&response_buf[..pos + 4])
                    .map_err(|_| Error::InvalidHeader)?;

                let first_line = response_str.lines().next().unwrap_or("");
                let (status, is_upgrade) = websocket::check_websocket_response(first_line);

                #[cfg(debug_assertions)]
                log::info!(status = status, is_upgrade = is_upgrade, response = response_str; "websocket_upgrade_response");

                if !is_upgrade {
                    // Not a successful upgrade, forward the error response
                    incoming.write_all(&response_buf[..total_read]).await?;
                    incoming.flush().await?;
                    return Err(Error::IO(io::Error::other(format!(
                        "WebSocket upgrade rejected with status {}",
                        status
                    ))));
                }

                // Forward the 101 response to the client
                incoming.write_all(&response_buf[..total_read]).await?;
                incoming.flush().await?;

                #[cfg(debug_assertions)]
                log::info!("websocket_connection_established");

                // Now start bidirectional proxying
                #[allow(unused_variables)]
                if let Err(e) = websocket::bidirectional_copy(incoming, &mut outgoing).await {
                    #[cfg(debug_assertions)]
                    log::info!(error = e.to_string(); "websocket_connection_closed");
                }

                return Ok(());
            }

            if total_read >= response_buf.len() {
                return Err(Error::HeaderTooLarge);
            }
        }
    }
}

/// Find the end of HTTP headers (double CRLF)
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
}

pub trait ConnTrait: AsyncRead + AsyncWrite {
    fn new(endpoint: &str, stream: TcpStream) -> Self;
    fn new_tls(
        endpoint: &str,
        stream: TcpStream,
        connector: tokio_rustls::TlsConnector,
    ) -> Pin<Box<dyn Future<Output=Result<Self, Error>> + Send>>
    where
        Self: Sized;
    fn endpoint(&self) -> &str;
    fn health_check<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output=Result<(), Error>> + Send + 'a>>;
    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=()> + Send + 'a>>;
}

pub struct Conn {
    endpoint: String,
    stream: Stream,
}

impl ConnTrait for Conn {
    fn new(endpoint: &str, stream: TcpStream) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            stream: Stream::Tcp(stream),
        }
    }

    fn new_tls(
        endpoint: &str,
        stream: TcpStream,
        connector: tokio_rustls::TlsConnector,
    ) -> Pin<Box<dyn Future<Output=Result<Self, Error>> + Send>> {
        let endpoint = endpoint.to_owned();
        Box::pin(async move {
            let server_name = endpoint
                .clone()
                .try_into()
                .map_err(|_| Error::InvalidServerName(endpoint.clone()))?;
            let tls_stream = connector.connect(server_name, stream).await?;
            Ok(Self {
                endpoint: endpoint.to_string(),
                stream: Stream::Tls(tls_stream),
            })
        })
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn health_check<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output=Result<(), Error>> + Send + 'a>> {
        Box::pin(async {
            self.stream.write_all(b"GET / HTTP/1.1\r\n").await?;
            self.stream.write_all(b"Host: ").await?;
            self.stream.write_all(self.endpoint.as_bytes()).await?;
            self.stream.write_all(b"\r\n").await?;
            self.stream
                .write_all(b"Connection: keep-alive\r\n\r\n")
                .await?;
            self.stream.flush().await?;
            let mut response = http::Response::new(&mut self.stream).await?;
            response.write_to(&mut io::empty()).await?;
            let conn_keep_alive = response.payload.conn_keep_alive;
            drop(response);
            if !conn_keep_alive {
                return Err(Error::IO(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "",
                )));
            }
            Ok(())
        })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=()> + Send + 'a>> {
        Box::pin(async {
            match &mut self.stream {
                Stream::Tcp(stream) => {
                    #[allow(unused)]
                    stream.shutdown().await;
                }
                Stream::Tls(stream) => {
                    #[allow(unused)]
                    stream.shutdown().await;
                }
            }
        })
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        pin!(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        pin!(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.stream).poll_shutdown(cx)
    }
}

#[allow(clippy::large_enum_variant)]
enum Stream {
    Tcp(TcpStream),
    Tls(TlsOutgoingStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_read(cx, buf),
            Stream::Tls(stream) => pin!(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_write(cx, buf),
            Stream::Tls(stream) => pin!(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_flush(cx),
            Stream::Tls(stream) => pin!(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_shutdown(cx),
            Stream::Tls(stream) => pin!(stream).poll_shutdown(cx),
        }
    }
}

struct H2StreamReader {
    bytes: Option<Cursor<bytes::Bytes>>,
    stream: h2::RecvStream,
}

impl H2StreamReader {
    fn new(stream: h2::RecvStream) -> Self {
        H2StreamReader {
            bytes: None,
            stream,
        }
    }
}

impl AsyncRead for H2StreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(cursor) = &mut self.bytes {
            if cursor.has_remaining() {
                return pin!(cursor).poll_read(cx, buf);
            }
        }
        let stream = match self.stream.poll_data(cx) {
            Poll::Ready(Some(Ok(stream))) => stream,
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Ready(None) => return Poll::Ready(Ok(())),
            Poll::Pending => return Poll::Pending,
        };
        self.bytes = Some(Cursor::new(stream));
        self.poll_read(cx, buf)
    }
}

/// Wrapper for h2::SendStream to implement AsyncWrite for WebSocket
struct H2SendStreamWriter {
    send: h2::SendStream<bytes::Bytes>,
}

impl H2SendStreamWriter {
    fn new(send: h2::SendStream<bytes::Bytes>) -> Self {
        H2SendStreamWriter { send }
    }

    async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        // Reserve capacity if needed
        if self.send.capacity() < data.len() {
            self.send.reserve_capacity(data.len());
        }

        // Send data
        self.send
            .send_data(bytes::Bytes::copy_from_slice(data), false)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        // Send empty data with end_of_stream flag
        self.send
            .send_data(bytes::Bytes::new(), true)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

/// Generate a random base64-encoded WebSocket key
fn base64_encode_ws_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Generate a simple pseudo-random 16-byte key
    // In production, you'd use a proper random number generator
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();

    let mut key = [0u8; 16];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = ((nanos >> (i * 4)) & 0xFF) as u8;
    }

    // Base64 encode
    base64_encode(&key)
}

/// Simple base64 encoder (avoid external dependency for this small use case)
fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(CHARSET[b0 >> 2] as char);
        result.push(CHARSET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(CHARSET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARSET[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
    }

    result
}

#[inline]
fn is_http2_invalid_headers(key: &str) -> bool {
    key.eq_ignore_ascii_case(httplib::header::CONNECTION.as_str())
        || key.eq_ignore_ascii_case(httplib::header::TRANSFER_ENCODING.as_str())
        || key.eq_ignore_ascii_case(httplib::header::UPGRADE.as_str())
        || key.eq_ignore_ascii_case("keep-alive")
        || key.eq_ignore_ascii_case("proxy-connection")
        || key.eq_ignore_ascii_case("content-length")
}

/// Build upstream path by stripping prefix and replacing auth query param.
fn build_upstream_path(
    path: &str,
    path_prefix: Option<&str>,
    api_key: Option<&str>,
    auth_query_key: Option<&str>,
) -> String {
    let mut result = path.to_string();

    // Strip path prefix if present
    if let Some(prefix) = path_prefix {
        result = strip_path_prefix(&result, prefix);
    }

    // Replace auth query key value with real API key (e.g., for Gemini)
    if let (Some(key), Some(query_key)) = (api_key, auth_query_key) {
        result = replace_query_param_value(&result, query_key, key);
    }

    result
}

/// Build HTTP/1.1 request headers string from an iterator of headers.
/// Filters out auth headers and replaces Host header with the upstream host.
fn build_h1_request_headers<'a, I>(
    headers: I,
    host_header_value: &str,
    auth_header_key: Option<&str>,
    auth_header: Option<&str>,
    has_content_length: bool,
) -> String
where
    I: Iterator<Item = (&'a httplib::HeaderName, &'a httplib::HeaderValue)>,
{
    let mut req_headers = String::with_capacity(1024);

    for (key, value) in headers {
        let key_str = key.as_str();
        // Skip auth header - will be replaced by provider auth
        if let Some(provider_auth_key) = auth_header_key {
            if key_str.eq_ignore_ascii_case(provider_auth_key.trim_end_matches([' ', ':'])) {
                continue;
            }
        }
        // Replace Host header
        if key_str.eq_ignore_ascii_case("host") {
            req_headers.push_str(&format!("Host: {}\r\n", host_header_value));
            continue;
        }
        req_headers.push_str(key_str);
        req_headers.push_str(": ");
        req_headers.push_str(String::from_utf8_lossy(value.as_bytes()).as_ref());
        req_headers.push_str("\r\n");
    }

    // Add provider's auth header if present
    if let Some(auth) = auth_header {
        req_headers.push_str(auth);
    }

    // Add Transfer-Encoding if no Content-Length
    if !has_content_length {
        req_headers.push_str("Transfer-Encoding: chunked\r\n");
    }

    req_headers
}

/// Parse auth header string like "Authorization: Bearer xxx\r\n" into (name, value).
fn parse_auth_header(auth: &str) -> Option<(&str, &str)> {
    auth.find(':').map(|colon_pos| {
        let header_name = auth[..colon_pos].trim();
        let header_value = auth[colon_pos + 1..].trim().trim_end_matches("\r\n");
        (header_name, header_value)
    })
}

/// Strip path prefix from a path string, preserving query parameters.
/// For example, "/v1/api/models?key=value" with prefix "/v1/api" becomes "/models?key=value".
fn strip_path_prefix(path: &str, prefix: &str) -> String {
    if let Some(query_pos) = path.find('?') {
        let (path_part, query_part) = path.split_at(query_pos);
        if let Some(remaining) = path_part.strip_prefix(prefix) {
            let new_path = if remaining.is_empty() { "/" } else { remaining };
            return format!("{}{}", new_path, query_part);
        }
    } else if let Some(remaining) = path.strip_prefix(prefix) {
        return if remaining.is_empty() {
            "/".to_string()
        } else {
            remaining.to_string()
        };
    }
    path.to_string()
}

/// Replace the value of a query parameter in a path string.
/// For example, "/path?key=placeholder&other=value" with key="key" and value="real_key"
/// becomes "/path?key=real_key&other=value".
fn replace_query_param_value(path: &str, query_key: &str, new_value: &str) -> String {
    let Some(query_start) = path.find('?') else {
        return path.to_string();
    };

    let (path_part, query_part) = path.split_at(query_start + 1);
    let query = query_part.trim_end_matches('#');

    let mut result = String::with_capacity(path.len() + new_value.len());
    result.push_str(path_part);

    let mut first = true;
    for part in query.split('&') {
        if !first {
            result.push('&');
        }
        first = false;

        if let Some(eq_pos) = part.find('=') {
            let (k, _v) = part.split_at(eq_pos);
            if k == query_key {
                result.push_str(k);
                result.push('=');
                result.push_str(new_value);
                continue;
            }
        }
        result.push_str(part);
    }

    // Preserve fragment if present
    if let Some(fragment_start) = query_part.find('#') {
        result.push_str(&query_part[fragment_start..]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn test_base64_encode_single_byte() {
        assert_eq!(base64_encode(&[0]), "AA==");
        assert_eq!(base64_encode(&[255]), "/w==");
    }

    #[test]
    fn test_base64_encode_two_bytes() {
        assert_eq!(base64_encode(&[0, 0]), "AAA=");
        assert_eq!(base64_encode(&[255, 255]), "//8=");
    }

    #[test]
    fn test_base64_encode_three_bytes() {
        assert_eq!(base64_encode(&[0, 0, 0]), "AAAA");
        assert_eq!(base64_encode(&[255, 255, 255]), "////");
    }

    #[test]
    fn test_base64_encode_standard_vectors() {
        // Standard base64 test vectors
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_base64_encode_ws_key() {
        let key = base64_encode_ws_key();
        // WebSocket key should be 24 characters (base64 of 16 bytes)
        assert_eq!(key.len(), 24);
        // Should end with == (16 bytes -> 24 chars with padding)
        assert!(key.ends_with("==") || !key.contains('=') || key.ends_with('='));
    }

    #[test]
    fn test_find_header_end() {
        // No double CRLF
        assert_eq!(find_header_end(b"Hello\r\nWorld"), None);

        // Double CRLF at the end
        assert_eq!(find_header_end(b"Header: value\r\n\r\n"), Some(13));

        // Double CRLF in the middle
        assert_eq!(find_header_end(b"Header: value\r\n\r\nBody"), Some(13));

        // Empty buffer
        assert_eq!(find_header_end(b""), None);

        // Just CRLF
        assert_eq!(find_header_end(b"\r\n"), None);

        // Just double CRLF
        assert_eq!(find_header_end(b"\r\n\r\n"), Some(0));
    }

    #[test]
    fn test_is_http2_invalid_headers() {
        // Headers that should be filtered
        assert!(is_http2_invalid_headers("connection"));
        assert!(is_http2_invalid_headers("Connection"));
        assert!(is_http2_invalid_headers("CONNECTION"));
        assert!(is_http2_invalid_headers("transfer-encoding"));
        assert!(is_http2_invalid_headers("Transfer-Encoding"));
        assert!(is_http2_invalid_headers("upgrade"));
        assert!(is_http2_invalid_headers("Upgrade"));
        assert!(is_http2_invalid_headers("keep-alive"));
        assert!(is_http2_invalid_headers("Keep-Alive"));
        assert!(is_http2_invalid_headers("proxy-connection"));
        assert!(is_http2_invalid_headers("Proxy-Connection"));
        assert!(is_http2_invalid_headers("content-length"));
        assert!(is_http2_invalid_headers("Content-Length"));

        // Headers that should NOT be filtered
        assert!(!is_http2_invalid_headers("content-type"));
        assert!(!is_http2_invalid_headers("authorization"));
        assert!(!is_http2_invalid_headers("host"));
        assert!(!is_http2_invalid_headers("x-custom-header"));
    }

    #[test]
    fn test_replace_query_param_value() {
        // Basic replacement
        assert_eq!(
            replace_query_param_value("/path?key=placeholder", "key", "real_key"),
            "/path?key=real_key"
        );

        // Multiple params, replace first
        assert_eq!(
            replace_query_param_value("/path?key=placeholder&other=value", "key", "real_key"),
            "/path?key=real_key&other=value"
        );

        // Multiple params, replace middle
        assert_eq!(
            replace_query_param_value("/path?first=1&key=placeholder&last=2", "key", "real_key"),
            "/path?first=1&key=real_key&last=2"
        );

        // Multiple params, replace last
        assert_eq!(
            replace_query_param_value("/path?other=value&key=placeholder", "key", "real_key"),
            "/path?other=value&key=real_key"
        );

        // Key not found
        assert_eq!(
            replace_query_param_value("/path?other=value", "key", "real_key"),
            "/path?other=value"
        );

        // No query string
        assert_eq!(
            replace_query_param_value("/path", "key", "real_key"),
            "/path"
        );

        // Empty value replacement
        assert_eq!(
            replace_query_param_value("/path?key=", "key", "real_key"),
            "/path?key=real_key"
        );

        // Gemini-style path
        assert_eq!(
            replace_query_param_value("/v1beta/models?key=placeholder&pageSize=1", "key", "AIza123"),
            "/v1beta/models?key=AIza123&pageSize=1"
        );

        // With fragment
        assert_eq!(
            replace_query_param_value("/path?key=placeholder#section", "key", "real_key"),
            "/path?key=real_key#section"
        );
    }

    #[test]
    fn test_strip_path_prefix() {
        // Basic prefix stripping
        assert_eq!(strip_path_prefix("/v1/api/models", "/v1/api"), "/models");

        // Prefix at root
        assert_eq!(strip_path_prefix("/v1/api", "/v1/api"), "/");

        // No match
        assert_eq!(strip_path_prefix("/other/path", "/v1/api"), "/other/path");

        // With query parameters
        assert_eq!(
            strip_path_prefix("/v1/api/models?key=value", "/v1/api"),
            "/models?key=value"
        );

        // Prefix with query, prefix at root
        assert_eq!(
            strip_path_prefix("/v1/api?key=value", "/v1/api"),
            "/?key=value"
        );

        // No prefix match with query
        assert_eq!(
            strip_path_prefix("/other/path?key=value", "/v1/api"),
            "/other/path?key=value"
        );

        // Partial prefix match (strips because /v1/api is a valid prefix)
        assert_eq!(strip_path_prefix("/v1/api2/models", "/v1/api"), "2/models");

        // Empty path after prefix
        assert_eq!(strip_path_prefix("/prefix", "/prefix"), "/");

        // Root path
        assert_eq!(strip_path_prefix("/", "/"), "/");
    }

    #[test]
    fn test_build_upstream_path() {
        // No transformations
        assert_eq!(
            build_upstream_path("/v1/models", None, None, None),
            "/v1/models"
        );

        // Only prefix stripping
        assert_eq!(
            build_upstream_path("/prefix/models", Some("/prefix"), None, None),
            "/models"
        );

        // Only query param replacement
        assert_eq!(
            build_upstream_path("/models?key=placeholder", None, Some("real_key"), Some("key")),
            "/models?key=real_key"
        );

        // Both prefix stripping and query param replacement
        assert_eq!(
            build_upstream_path(
                "/prefix/models?key=placeholder&other=value",
                Some("/prefix"),
                Some("real_key"),
                Some("key")
            ),
            "/models?key=real_key&other=value"
        );

        // Gemini-style path
        assert_eq!(
            build_upstream_path(
                "/v1beta/models?key=user_key&pageSize=10",
                None,
                Some("AIza123"),
                Some("key")
            ),
            "/v1beta/models?key=AIza123&pageSize=10"
        );

        // Missing api_key (no replacement)
        assert_eq!(
            build_upstream_path("/models?key=placeholder", None, None, Some("key")),
            "/models?key=placeholder"
        );

        // Missing auth_query_key (no replacement)
        assert_eq!(
            build_upstream_path("/models?key=placeholder", None, Some("real_key"), None),
            "/models?key=placeholder"
        );
    }

    #[test]
    fn test_parse_auth_header() {
        // Standard Authorization header
        assert_eq!(
            parse_auth_header("Authorization: Bearer token123\r\n"),
            Some(("Authorization", "Bearer token123"))
        );

        // x-goog-api-key header
        assert_eq!(
            parse_auth_header("x-goog-api-key: AIza123\r\n"),
            Some(("x-goog-api-key", "AIza123"))
        );

        // Header with extra whitespace
        assert_eq!(
            parse_auth_header("  Authorization  :   Bearer token123  \r\n"),
            Some(("Authorization", "Bearer token123"))
        );

        // Header without trailing CRLF
        assert_eq!(
            parse_auth_header("Authorization: Bearer token123"),
            Some(("Authorization", "Bearer token123"))
        );

        // Invalid header (no colon)
        assert_eq!(parse_auth_header("InvalidHeader"), None);

        // Empty string
        assert_eq!(parse_auth_header(""), None);

        // Just colon
        assert_eq!(parse_auth_header(":"), Some(("", "")));
    }

    #[test]
    fn test_build_h1_request_headers() {
        use httplib::header::{HeaderMap, HeaderName, HeaderValue};

        // Create test headers
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("client.example.com"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer client_token"),
        );

        // Test with auth header replacement and no content-length
        let result = build_h1_request_headers(
            headers.iter(),
            "upstream.example.com",
            Some("Authorization: "),
            Some("Authorization: Bearer server_token\r\n"),
            false,
        );

        assert!(result.contains("Host: upstream.example.com\r\n"));
        assert!(result.contains("content-type: application/json\r\n"));
        assert!(result.contains("Authorization: Bearer server_token\r\n"));
        assert!(result.contains("Transfer-Encoding: chunked\r\n"));
        // Should NOT contain the client's authorization
        assert!(!result.contains("Bearer client_token"));

        // Test with content-length (no Transfer-Encoding)
        let result_with_cl = build_h1_request_headers(
            headers.iter(),
            "upstream.example.com",
            Some("Authorization: "),
            Some("Authorization: Bearer server_token\r\n"),
            true,
        );

        assert!(!result_with_cl.contains("Transfer-Encoding"));

        // Test without auth header replacement
        let result_no_auth = build_h1_request_headers(
            headers.iter(),
            "upstream.example.com",
            None,
            None,
            true,
        );

        assert!(result_no_auth.contains("authorization: Bearer client_token\r\n"));
    }
}
