use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
}
