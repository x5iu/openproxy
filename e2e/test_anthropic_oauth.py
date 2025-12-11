"""
E2E tests for Anthropic OAuth authentication support.

This test suite validates:
1. Authorization: Bearer header is used instead of X-API-Key when api_key is $(command)
2. anthropic-beta: oauth-2025-04-20 header is added when using OAuth mode
3. Existing anthropic-beta header values are preserved and oauth value is appended

The test uses a mock upstream server to verify the headers are correctly set.
"""

import json
import os
import socket
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler


class MockAnthropicServer(BaseHTTPRequestHandler):
    """Mock server that validates OAuth headers and returns appropriate responses."""

    # Class variables to store validation results
    received_headers = {}
    validation_errors = []

    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def do_POST(self):
        # Store received headers for validation
        MockAnthropicServer.received_headers = dict(self.headers)

        # Validate Authorization header
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            MockAnthropicServer.validation_errors.append(
                f"Missing or invalid Authorization header: {auth_header}"
            )

        # Validate anthropic-beta header
        beta_header = self.headers.get("anthropic-beta", "")
        if "oauth-2025-04-20" not in beta_header:
            MockAnthropicServer.validation_errors.append(
                f"Missing oauth-2025-04-20 in anthropic-beta header: {beta_header}"
            )

        # Check that X-API-Key is NOT present
        if self.headers.get("X-API-Key"):
            MockAnthropicServer.validation_errors.append(
                f"X-API-Key header should not be present in OAuth mode"
            )

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # Return a mock response
        response = {
            "id": "msg_test123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello! OAuth auth validated."}],
            "model": "claude-3-sonnet-20240229",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 20},
        }

        response_body = json.dumps(response).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def do_GET(self):
        # Health check endpoint
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        self.send_response(404)
        self.end_headers()


def find_free_port():
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        return s.getsockname()[1]


def start_mock_server(port):
    """Start the mock server in a separate thread."""
    server = HTTPServer(("127.0.0.1", port), MockAnthropicServer)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server


def wait_for_server(host, port, timeout=5):
    """Wait for the server to be ready."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (socket.error, ConnectionRefusedError):
            time.sleep(0.1)
    return False


def test_oauth_headers_via_proxy():
    """
    Test that OAuth headers are correctly forwarded through the proxy.

    This test:
    1. Starts a mock upstream server
    2. Configures openproxy with an Anthropic provider using $(echo token) as api_key
    3. Sends a request through the proxy
    4. Verifies the upstream server receives correct headers
    """
    import httpx
    import subprocess
    import tempfile
    import yaml

    print(f"\n{'='*60}")
    print("Testing Anthropic OAuth Header Forwarding")
    print("=" * 60)

    # Find free ports
    mock_port = find_free_port()
    proxy_http_port = find_free_port()

    # Start mock server
    print(f"Starting mock upstream server on port {mock_port}...")
    MockAnthropicServer.received_headers = {}
    MockAnthropicServer.validation_errors = []
    mock_server = start_mock_server(mock_port)

    if not wait_for_server("127.0.0.1", mock_port):
        print("Failed to start mock server")
        sys.exit(1)

    print(f"Mock server ready on port {mock_port}")

    # Create proxy config
    config = {
        "http_port": proxy_http_port,
        "providers": [
            {
                "type": "anthropic",
                "host": "anthropic-oauth.local",
                "endpoint": "127.0.0.1",
                "port": mock_port,
                "tls": False,
                # OAuth mode: api_key is a command
                "api_key": "$(echo test-oauth-token-12345)",
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    print(f"Config written to {config_path}")
    print(f"Starting proxy on HTTP port {proxy_http_port}...")

    # Start the proxy
    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        # Wait for proxy to be ready
        if not wait_for_server("127.0.0.1", proxy_http_port, timeout=30):
            stdout, stderr = proxy_process.communicate(timeout=1)
            print(f"Proxy stdout: {stdout.decode()}")
            print(f"Proxy stderr: {stderr.decode()}")
            print("Failed to start proxy")
            sys.exit(1)

        print("Proxy ready")

        # Send request through proxy
        print("Sending test request through proxy...")
        with httpx.Client(
            base_url=f"http://127.0.0.1:{proxy_http_port}", timeout=30, proxy=None
        ) as client:
            response = client.post(
                "/v1/messages",
                headers={
                    "Host": "anthropic-oauth.local",
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": "claude-3-sonnet-20240229",
                    "max_tokens": 100,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text[:200]}")

        # Check validation results
        print("\n--- Received Headers at Upstream ---")
        for key, value in MockAnthropicServer.received_headers.items():
            print(f"  {key}: {value}")

        print("\n--- Validation Results ---")
        if MockAnthropicServer.validation_errors:
            for error in MockAnthropicServer.validation_errors:
                print(f"  ERROR: {error}")
            sys.exit(1)
        else:
            # Additional assertions
            auth = MockAnthropicServer.received_headers.get("Authorization", "")
            assert auth == "Bearer test-oauth-token-12345", f"Unexpected Authorization: {auth}"

            beta = MockAnthropicServer.received_headers.get("anthropic-beta", "")
            assert "oauth-2025-04-20" in beta, f"Missing oauth-2025-04-20 in: {beta}"

            print("  All headers validated successfully!")
            print("\u2713 OAuth header forwarding test passed!")

    finally:
        # Cleanup
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()

        os.unlink(config_path)


def test_oauth_with_existing_beta_header():
    """
    Test that existing anthropic-beta header values are preserved.
    """
    import httpx
    import subprocess
    import tempfile
    import yaml

    print(f"\n{'='*60}")
    print("Testing Anthropic OAuth with Existing Beta Header")
    print("=" * 60)

    # Find free ports
    mock_port = find_free_port()
    proxy_http_port = find_free_port()

    # Start mock server
    print(f"Starting mock upstream server on port {mock_port}...")
    MockAnthropicServer.received_headers = {}
    MockAnthropicServer.validation_errors = []
    mock_server = start_mock_server(mock_port)

    if not wait_for_server("127.0.0.1", mock_port):
        print("Failed to start mock server")
        sys.exit(1)

    # Create proxy config
    config = {
        "http_port": proxy_http_port,
        "providers": [
            {
                "type": "anthropic",
                "host": "anthropic-oauth.local",
                "endpoint": "127.0.0.1",
                "port": mock_port,
                "tls": False,
                "api_key": "$(echo oauth-token)",
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    # Start the proxy
    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        if not wait_for_server("127.0.0.1", proxy_http_port, timeout=30):
            print("Failed to start proxy")
            sys.exit(1)

        # Send request with existing anthropic-beta header
        print("Sending test request with existing anthropic-beta header...")
        with httpx.Client(
            base_url=f"http://127.0.0.1:{proxy_http_port}", timeout=30, proxy=None
        ) as client:
            response = client.post(
                "/v1/messages",
                headers={
                    "Host": "anthropic-oauth.local",
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                    "anthropic-beta": "max-tokens-3-5-sonnet-2024-07-15",
                },
                json={
                    "model": "claude-3-sonnet-20240229",
                    "max_tokens": 100,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        print(f"Response status: {response.status_code}")

        # Check that both beta values are present
        beta = MockAnthropicServer.received_headers.get("anthropic-beta", "")
        print(f"Received anthropic-beta: {beta}")

        assert "max-tokens-3-5-sonnet-2024-07-15" in beta, f"Missing original beta value in: {beta}"
        assert "oauth-2025-04-20" in beta, f"Missing oauth-2025-04-20 in: {beta}"

        print("\u2713 Existing beta header preservation test passed!")

    finally:
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()

        os.unlink(config_path)


def test_standard_mode_uses_x_api_key():
    """
    Test that standard mode (non-OAuth) still uses X-API-Key header.
    """
    import httpx
    import subprocess
    import tempfile
    import yaml

    print(f"\n{'='*60}")
    print("Testing Anthropic Standard Mode (X-API-Key)")
    print("=" * 60)

    # Find free ports
    mock_port = find_free_port()
    proxy_http_port = find_free_port()

    # Custom handler for standard mode
    class StandardModeHandler(BaseHTTPRequestHandler):
        received_headers = {}

        def log_message(self, format, *args):
            pass

        def do_POST(self):
            StandardModeHandler.received_headers = dict(self.headers)

            response = json.dumps({"id": "msg_test", "content": [{"type": "text", "text": "OK"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    # Start mock server
    server = HTTPServer(("127.0.0.1", mock_port), StandardModeHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    if not wait_for_server("127.0.0.1", mock_port):
        print("Failed to start mock server")
        sys.exit(1)

    # Create proxy config with standard api_key (not $(command))
    config = {
        "http_port": proxy_http_port,
        "providers": [
            {
                "type": "anthropic",
                "host": "anthropic-standard.local",
                "endpoint": "127.0.0.1",
                "port": mock_port,
                "tls": False,
                "api_key": "sk-ant-api-key-standard-12345",  # Standard key, not $(command)
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        if not wait_for_server("127.0.0.1", proxy_http_port, timeout=30):
            print("Failed to start proxy")
            sys.exit(1)

        # Send request
        print("Sending test request...")
        with httpx.Client(
            base_url=f"http://127.0.0.1:{proxy_http_port}", timeout=30, proxy=None
        ) as client:
            response = client.post(
                "/v1/messages",
                headers={
                    "Host": "anthropic-standard.local",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "claude-3-sonnet-20240229",
                    "max_tokens": 100,
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        print(f"Response status: {response.status_code}")

        # Verify X-API-Key is used (not Authorization Bearer)
        x_api_key = StandardModeHandler.received_headers.get("X-API-Key", "")
        auth_header = StandardModeHandler.received_headers.get("Authorization", "")
        beta_header = StandardModeHandler.received_headers.get("anthropic-beta", "")

        print(f"X-API-Key: {x_api_key}")
        print(f"Authorization: {auth_header}")
        print(f"anthropic-beta: {beta_header}")

        assert x_api_key == "sk-ant-api-key-standard-12345", f"Unexpected X-API-Key: {x_api_key}"
        assert not auth_header, f"Authorization header should not be present: {auth_header}"
        assert "oauth-2025-04-20" not in beta_header, f"oauth-2025-04-20 should not be in standard mode: {beta_header}"

        print("\u2713 Standard mode test passed!")

    finally:
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()

        os.unlink(config_path)


if __name__ == "__main__":
    test_oauth_headers_via_proxy()
    test_oauth_with_existing_beta_header()
    test_standard_mode_uses_x_api_key()

    print("\n" + "=" * 60)
    print("\u2713 All Anthropic OAuth tests passed!")
    print("=" * 60)
