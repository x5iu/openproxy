use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// WebSocket upgrade request information
#[derive(Debug, Clone)]
pub struct WebSocketUpgrade {
    pub sec_websocket_key: String,
    pub sec_websocket_version: String,
    pub sec_websocket_protocol: Option<String>,
    pub sec_websocket_extensions: Option<String>,
}


/// Bidirectional copy between two streams
/// This is used after WebSocket handshake to proxy data in both directions
pub async fn bidirectional_copy<C, S>(
    client: &mut C,
    server: &mut S,
) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let client_to_server = async {
        let result = tokio::io::copy(&mut client_read, &mut server_write).await;
        // Shutdown the write side to signal EOF
        let _ = server_write.shutdown().await;
        result
    };

    let server_to_client = async {
        let result = tokio::io::copy(&mut server_read, &mut client_write).await;
        // Shutdown the write side to signal EOF
        let _ = client_write.shutdown().await;
        result
    };

    tokio::try_join!(client_to_server, server_to_client)
}

/// WebSocket-specific bidirectional copy that handles the streams without splitting
/// This version is more efficient for cases where we own both streams
pub async fn websocket_proxy<C, S>(
    mut client: C,
    mut server: S,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut client_buf = vec![0u8; 8192];
    let mut server_buf = vec![0u8; 8192];

    loop {
        tokio::select! {
            biased;

            result = client.read(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        // Client closed, shutdown server write
                        let _ = server.shutdown().await;
                        return Ok(());
                    }
                    Ok(n) => {
                        server.write_all(&client_buf[..n]).await?;
                        server.flush().await?;
                    }
                    Err(e) => {
                        let _ = server.shutdown().await;
                        return Err(e);
                    }
                }
            }

            result = server.read(&mut server_buf) => {
                match result {
                    Ok(0) => {
                        // Server closed, shutdown client write
                        let _ = client.shutdown().await;
                        return Ok(());
                    }
                    Ok(n) => {
                        client.write_all(&server_buf[..n]).await?;
                        client.flush().await?;
                    }
                    Err(e) => {
                        let _ = client.shutdown().await;
                        return Err(e);
                    }
                }
            }
        }
    }
}

/// Parse HTTP response status line and check if it's a valid WebSocket upgrade response
/// Returns (status_code, is_valid_upgrade)
pub fn check_websocket_response(response_line: &str) -> (u16, bool) {
    // Parse "HTTP/1.1 101 Switching Protocols"
    let parts: Vec<&str> = response_line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        if let Ok(status) = parts[1].parse::<u16>() {
            return (status, status == 101);
        }
    }
    (0, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_websocket_response_valid() {
        let (status, is_valid) = check_websocket_response("HTTP/1.1 101 Switching Protocols");
        assert_eq!(status, 101);
        assert!(is_valid);
    }

    #[test]
    fn test_check_websocket_response_not_upgrade() {
        let (status, is_valid) = check_websocket_response("HTTP/1.1 200 OK");
        assert_eq!(status, 200);
        assert!(!is_valid);

        let (status, is_valid) = check_websocket_response("HTTP/1.1 400 Bad Request");
        assert_eq!(status, 400);
        assert!(!is_valid);
    }

    #[test]
    fn test_check_websocket_response_invalid_format() {
        let (status, is_valid) = check_websocket_response("invalid response");
        assert_eq!(status, 0);
        assert!(!is_valid);

        let (status, is_valid) = check_websocket_response("");
        assert_eq!(status, 0);
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_bidirectional_copy() {
        // Create mock streams using duplex
        let (mut client, mut server) = tokio::io::duplex(1024);

        // Spawn a task that writes to server and reads from it
        let server_handle = tokio::spawn(async move {
            server.write_all(b"Hello from server").await.unwrap();
            server.shutdown().await.unwrap();
            let mut buf = vec![0u8; 100];
            let n = server.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });

        // Write to client and read response
        client.write_all(b"Hello from client").await.unwrap();
        client.shutdown().await.unwrap();

        let mut buf = vec![0u8; 100];
        let n = client.read(&mut buf).await.unwrap();
        buf.truncate(n);

        assert_eq!(&buf, b"Hello from server");

        let server_received = server_handle.await.unwrap();
        assert_eq!(&server_received, b"Hello from client");
    }

    #[test]
    fn test_websocket_upgrade_struct() {
        let upgrade = WebSocketUpgrade {
            sec_websocket_key: "test-key".to_string(),
            sec_websocket_version: "13".to_string(),
            sec_websocket_protocol: Some("chat".to_string()),
            sec_websocket_extensions: Some("permessage-deflate".to_string()),
        };

        assert_eq!(upgrade.sec_websocket_key, "test-key");
        assert_eq!(upgrade.sec_websocket_version, "13");
        assert_eq!(upgrade.sec_websocket_protocol, Some("chat".to_string()));
        assert_eq!(upgrade.sec_websocket_extensions, Some("permessage-deflate".to_string()));

        // Test Clone
        let cloned = upgrade.clone();
        assert_eq!(cloned.sec_websocket_key, upgrade.sec_websocket_key);
    }

    #[tokio::test]
    async fn test_websocket_proxy() {
        // Test the websocket proxy function with duplex streams
        let (client_stream, proxy_client_side) = tokio::io::duplex(1024);
        let (proxy_server_side, server_stream) = tokio::io::duplex(1024);

        // Spawn the proxy
        let proxy_handle = tokio::spawn(async move {
            let mut client = proxy_client_side;
            let mut server = proxy_server_side;
            websocket_proxy(client, server).await
        });

        // Spawn server that echoes data
        let server_handle = tokio::spawn(async move {
            let mut server = server_stream;
            let mut buf = vec![0u8; 100];
            let n = server.read(&mut buf).await.unwrap();
            if n > 0 {
                server.write_all(&buf[..n]).await.unwrap();
                server.flush().await.unwrap();
            }
            server.shutdown().await.unwrap();
        });

        // Client sends and receives
        let mut client = client_stream;
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();

        // Give time for the echo
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let mut buf = vec![0u8; 100];
        let n = client.read(&mut buf).await.unwrap();

        assert_eq!(&buf[..n], b"ping");

        client.shutdown().await.unwrap();

        // Wait for handles
        let _ = server_handle.await;
        let _ = proxy_handle.await;
    }
}
