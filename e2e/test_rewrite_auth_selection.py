"""
E2E tests for path rewriting with auth-based provider selection.

This tests the scenario where multiple providers match the same base host but have
different path prefixes and different auth_keys. The proxy must:
1. Select the correct provider based on authentication
2. Apply the correct path rewriting (if any) for that specific provider

Without this fix, the proxy would select the correct provider for authentication,
but might use a different provider's path rewriting rules, causing inconsistent behavior.

Test setup:
- Provider 1: host=rewrite-auth.local:PORT/v1, auth_key=sk-rewrite-key-1, port=9006
  - Path prefix /v1 should be stripped from requests
- Provider 2: host=rewrite-auth.local:PORT (no path prefix), auth_key=sk-rewrite-key-2, port=9007
  - No path stripping

Expected behavior:
- Request with sk-rewrite-key-1 to /v1/test -> goes to port 9006, path becomes /test
- Request with sk-rewrite-key-2 to /v1/test -> goes to port 9007, path stays /v1/test
"""

import os
import sys
import json
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Configuration from environment
HTTPS_PORT = int(os.environ.get("PROXY_HTTPS_PORT", "8443"))
HTTP_PORT = int(os.environ.get("PROXY_HTTP_PORT", "8080"))
SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE", "")

# Echo server ports
ECHO_PORT_WITH_REWRITE = 9006  # Provider with /v1 path prefix
ECHO_PORT_NO_REWRITE = 9007    # Provider without path prefix


class EchoHandler(BaseHTTPRequestHandler):
    """HTTP handler that echoes the request path and identifies the server."""

    protocol_version = "HTTP/1.1"
    server_id = "unknown"

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def _handle_request(self, method):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        response = {
            "server_id": self.server_id,
            "received_path": self.path,
            "method": method,
            "headers": {k: v for k, v in self.headers.items()},
        }
        body = json.dumps(response).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Suppress logging


def create_echo_server(port, server_id):
    """Create an echo server with a specific server_id."""
    class Handler(EchoHandler):
        pass
    Handler.server_id = server_id
    return HTTPServer(("127.0.0.1", port), Handler)


def is_port_in_use(port):
    """Check if a port is already in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def start_echo_servers():
    """Start echo servers for testing if not already running."""
    servers = []
    threads = []

    if not is_port_in_use(ECHO_PORT_WITH_REWRITE):
        server1 = create_echo_server(ECHO_PORT_WITH_REWRITE, "provider_with_rewrite")
        thread1 = threading.Thread(target=server1.serve_forever, daemon=True)
        thread1.start()
        servers.append(server1)
        threads.append(thread1)
        print(f"Started echo server on port {ECHO_PORT_WITH_REWRITE} (with rewrite)")
    else:
        print(f"Echo server already running on port {ECHO_PORT_WITH_REWRITE}")

    if not is_port_in_use(ECHO_PORT_NO_REWRITE):
        server2 = create_echo_server(ECHO_PORT_NO_REWRITE, "provider_no_rewrite")
        thread2 = threading.Thread(target=server2.serve_forever, daemon=True)
        thread2.start()
        servers.append(server2)
        threads.append(thread2)
        print(f"Started echo server on port {ECHO_PORT_NO_REWRITE} (no rewrite)")
    else:
        print(f"Echo server already running on port {ECHO_PORT_NO_REWRITE}")

    return servers, threads


def test_rewrite_auth_selection():
    """Test that path rewriting uses the correct provider based on auth selection."""
    import httpx

    print("\n=== Testing path rewrite with auth-based provider selection ===\n")

    # Number of iterations for consistency testing
    iterations = 5

    # Test 1: HTTPS with sk-rewrite-key-1 (should use provider with /v1 prefix, path rewritten)
    print(f"Test 1: HTTPS with sk-rewrite-key-1 (x{iterations} iterations)...")
    with httpx.Client(verify=SSL_CERT_FILE, http2=True) as client:
        for i in range(iterations):
            resp = client.get(
                f"https://localhost:{HTTPS_PORT}/v1/test",
                headers={
                    "Host": f"rewrite-auth.local:{HTTPS_PORT}",
                    "Authorization": "Bearer sk-rewrite-key-1",
                },
            )
            assert resp.status_code == 200, f"Iteration {i+1}: Expected 200, got {resp.status_code}"
            data = resp.json()
            assert data["server_id"] == "provider_with_rewrite", \
                f"Iteration {i+1}: Expected provider_with_rewrite, got {data['server_id']}"
            assert data["received_path"] == "/test", \
                f"Iteration {i+1}: Expected /test (path rewritten), got {data['received_path']}"
    print(f"  -> All {iterations} requests routed correctly with path rewrite (/v1/test -> /test)")

    # Test 2: HTTPS with sk-rewrite-key-2 (should use provider without prefix, path preserved)
    print(f"Test 2: HTTPS with sk-rewrite-key-2 (x{iterations} iterations)...")
    with httpx.Client(verify=SSL_CERT_FILE, http2=True) as client:
        for i in range(iterations):
            resp = client.get(
                f"https://localhost:{HTTPS_PORT}/v1/test",
                headers={
                    "Host": f"rewrite-auth.local:{HTTPS_PORT}",
                    "Authorization": "Bearer sk-rewrite-key-2",
                },
            )
            assert resp.status_code == 200, f"Iteration {i+1}: Expected 200, got {resp.status_code}"
            data = resp.json()
            assert data["server_id"] == "provider_no_rewrite", \
                f"Iteration {i+1}: Expected provider_no_rewrite, got {data['server_id']}"
            assert data["received_path"] == "/v1/test", \
                f"Iteration {i+1}: Expected /v1/test (no rewrite), got {data['received_path']}"
    print(f"  -> All {iterations} requests routed correctly without path rewrite (/v1/test -> /v1/test)")

    # Test 3: HTTP/1.1 with sk-rewrite-key-1 (path rewritten)
    print(f"Test 3: HTTP/1.1 with sk-rewrite-key-1 (x{iterations} iterations)...")
    with httpx.Client() as client:
        for i in range(iterations):
            resp = client.get(
                f"http://localhost:{HTTP_PORT}/v1/test",
                headers={
                    "Host": f"rewrite-auth.local:{HTTP_PORT}",
                    "Authorization": "Bearer sk-rewrite-key-1",
                },
            )
            assert resp.status_code == 200, f"Iteration {i+1}: Expected 200, got {resp.status_code}"
            data = resp.json()
            assert data["server_id"] == "provider_with_rewrite", \
                f"Iteration {i+1}: Expected provider_with_rewrite, got {data['server_id']}"
            assert data["received_path"] == "/test", \
                f"Iteration {i+1}: Expected /test (path rewritten), got {data['received_path']}"
    print(f"  -> All {iterations} requests routed correctly with path rewrite")

    # Test 4: HTTP/1.1 with sk-rewrite-key-2 (path preserved)
    print(f"Test 4: HTTP/1.1 with sk-rewrite-key-2 (x{iterations} iterations)...")
    with httpx.Client() as client:
        for i in range(iterations):
            resp = client.get(
                f"http://localhost:{HTTP_PORT}/v1/test",
                headers={
                    "Host": f"rewrite-auth.local:{HTTP_PORT}",
                    "Authorization": "Bearer sk-rewrite-key-2",
                },
            )
            assert resp.status_code == 200, f"Iteration {i+1}: Expected 200, got {resp.status_code}"
            data = resp.json()
            assert data["server_id"] == "provider_no_rewrite", \
                f"Iteration {i+1}: Expected provider_no_rewrite, got {data['server_id']}"
            assert data["received_path"] == "/v1/test", \
                f"Iteration {i+1}: Expected /v1/test (no rewrite), got {data['received_path']}"
    print(f"  -> All {iterations} requests routed correctly without path rewrite")

    # Test 5: Invalid auth key (should return 401)
    print("Test 5: HTTPS with invalid auth key (should return 401)...")
    with httpx.Client(verify=SSL_CERT_FILE, http2=True) as client:
        resp = client.get(
            f"https://localhost:{HTTPS_PORT}/v1/test",
            headers={
                "Host": f"rewrite-auth.local:{HTTPS_PORT}",
                "Authorization": "Bearer invalid-key",
            },
        )
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    print("  -> Got 401 as expected")

    print("\n=== All tests passed! ===\n")


if __name__ == "__main__":
    # Start echo servers if running standalone
    servers, threads = start_echo_servers()

    try:
        test_rewrite_auth_selection()
    except Exception as e:
        print(f"\nTest failed: {e}")
        sys.exit(1)
    finally:
        # Cleanup servers
        for server in servers:
            server.shutdown()
