#!/usr/bin/env python3
"""
E2E tests for auth-during-provider-selection feature.

This tests the scenario where multiple providers match the same host/path,
but have different auth_keys. The proxy should authenticate against all
matching providers and select one that passes authentication.
"""

import os
import sys
import json
import subprocess
import tempfile
import time
import signal
import ssl
import socket
import urllib.request
import urllib.error
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading


# Test configuration
PROXY_BINARY = os.environ.get("OPENPROXY_BINARY", "../target/release/openproxy")
HTTPS_PORT = 18443
HTTP_PORT = 18080
UPSTREAM_PORT_1 = 19001
UPSTREAM_PORT_2 = 19002
UPSTREAM_PORT_FALLBACK = 19003


class EchoHandler(BaseHTTPRequestHandler):
    """Simple HTTP echo server that returns the server identifier."""
    protocol_version = "HTTP/1.1"
    server_id = "unknown"

    def do_GET(self):
        response = {
            "server_id": self.server_id,
            "path": self.path,
            "method": "GET",
        }
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_length)
        response = {
            "server_id": self.server_id,
            "path": self.path,
            "method": "POST",
            "body_length": content_length,
        }
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Suppress logging


def create_handler_class(server_id: str):
    """Create a handler class with a specific server_id."""
    class Handler(EchoHandler):
        pass
    Handler.server_id = server_id
    return Handler


def start_upstream_server(port: int, server_id: str) -> HTTPServer:
    """Start an upstream echo server."""
    handler = create_handler_class(server_id)
    server = HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def generate_cert(cert_file: str, key_file: str):
    """Generate a self-signed certificate."""
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,DNS:auth-test.local,IP:127.0.0.1"
    ], check=True, capture_output=True)


def create_config(cert_file: str, key_file: str, config_file: str):
    """Create proxy configuration with multiple providers for the same host."""
    config = f"""
cert_file: {cert_file}
private_key_file: {key_file}
https_port: {HTTPS_PORT}
http_port: {HTTP_PORT}

providers:
  # Provider 1: only accepts key "key-for-provider1"
  - type: openai
    host: auth-test.local
    endpoint: localhost
    port: {UPSTREAM_PORT_1}
    tls: false
    api_key: dummy-key-1
    auth_keys:
      - key-for-provider1

  # Provider 2: only accepts key "key-for-provider2"
  - type: openai
    host: auth-test.local
    endpoint: localhost
    port: {UPSTREAM_PORT_2}
    tls: false
    api_key: dummy-key-2
    auth_keys:
      - key-for-provider2

  # Fallback provider: accepts key "key-for-fallback"
  - type: openai
    host: auth-test.local
    endpoint: localhost
    port: {UPSTREAM_PORT_FALLBACK}
    tls: false
    api_key: dummy-key-fallback
    auth_keys:
      - key-for-fallback
    is_fallback: true
"""
    with open(config_file, "w") as f:
        f.write(config)


def wait_for_port(port: int, timeout: float = 10.0) -> bool:
    """Wait for a port to become available."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except (socket.error, ConnectionRefusedError):
            time.sleep(0.1)
    return False


def http_request(url: str, headers: dict, ssl_context=None) -> tuple:
    """Make an HTTP request and return (status_code, response_body)."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_auth_selects_correct_provider():
    """Test that authentication during provider selection works correctly."""
    print("\n=== Testing auth-during-provider-selection ===\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = os.path.join(tmpdir, "cert.pem")
        key_file = os.path.join(tmpdir, "key.pem")
        config_file = os.path.join(tmpdir, "config.yml")

        # Generate certificate
        print("Generating self-signed certificate...")
        generate_cert(cert_file, key_file)

        # Start upstream servers
        print("Starting upstream servers...")
        server1 = start_upstream_server(UPSTREAM_PORT_1, "provider1")
        server2 = start_upstream_server(UPSTREAM_PORT_2, "provider2")
        server_fallback = start_upstream_server(UPSTREAM_PORT_FALLBACK, "fallback")

        # Create config
        print("Creating proxy configuration...")
        create_config(cert_file, key_file, config_file)

        # Start proxy
        print("Starting openproxy...")
        proxy_proc = subprocess.Popen(
            [PROXY_BINARY, "start", "-c", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            # Wait for proxy to start
            if not wait_for_port(HTTPS_PORT):
                stdout, stderr = proxy_proc.communicate(timeout=5)
                print(f"Proxy stdout: {stdout.decode()}")
                print(f"Proxy stderr: {stderr.decode()}")
                raise RuntimeError("Proxy failed to start")

            print("Proxy started successfully\n")

            # Create SSL context that trusts our self-signed cert
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(cert_file)

            # Test 1: Request with key valid for provider1
            print("Test 1: Request with key valid for provider1...")
            status, data = http_request(
                f"https://localhost:{HTTPS_PORT}/v1/test",
                headers={
                    "Host": "auth-test.local",
                    "Authorization": "Bearer key-for-provider1",
                },
                ssl_context=ssl_context,
            )
            assert status == 200, f"Expected 200, got {status}"
            assert data["server_id"] == "provider1", f"Expected provider1, got {data['server_id']}"
            print(f"  -> Routed to: {data['server_id']} ✓")

            # Test 2: Request with key valid for provider2
            print("Test 2: Request with key valid for provider2...")
            status, data = http_request(
                f"https://localhost:{HTTPS_PORT}/v1/test",
                headers={
                    "Host": "auth-test.local",
                    "Authorization": "Bearer key-for-provider2",
                },
                ssl_context=ssl_context,
            )
            assert status == 200, f"Expected 200, got {status}"
            assert data["server_id"] == "provider2", f"Expected provider2, got {data['server_id']}"
            print(f"  -> Routed to: {data['server_id']} ✓")

            # Test 3: Request with key valid only for fallback
            # Non-fallback providers should fail auth, then fallback should be selected
            print("Test 3: Request with key valid only for fallback...")
            status, data = http_request(
                f"https://localhost:{HTTPS_PORT}/v1/test",
                headers={
                    "Host": "auth-test.local",
                    "Authorization": "Bearer key-for-fallback",
                },
                ssl_context=ssl_context,
            )
            assert status == 200, f"Expected 200, got {status}"
            assert data["server_id"] == "fallback", f"Expected fallback, got {data['server_id']}"
            print(f"  -> Routed to: {data['server_id']} ✓")

            # Test 4: Request with invalid key (should fail with 401)
            print("Test 4: Request with invalid key (should return 401)...")
            status, data = http_request(
                f"https://localhost:{HTTPS_PORT}/v1/test",
                headers={
                    "Host": "auth-test.local",
                    "Authorization": "Bearer invalid-key",
                },
                ssl_context=ssl_context,
            )
            assert status == 401, f"Expected 401, got {status}"
            print(f"  -> Got 401 as expected ✓")

            # Test 5: HTTP/1.1 tests
            print("Test 5: HTTP/1.1 request with key for provider1...")
            status, data = http_request(
                f"http://localhost:{HTTP_PORT}/v1/test",
                headers={
                    "Host": "auth-test.local",
                    "Authorization": "Bearer key-for-provider1",
                },
            )
            assert status == 200, f"Expected 200, got {status}"
            assert data["server_id"] == "provider1", f"Expected provider1, got {data['server_id']}"
            print(f"  -> Routed to: {data['server_id']} ✓")

            # Test 6: HTTP/1.1 with fallback key
            print("Test 6: HTTP/1.1 request with key for fallback...")
            status, data = http_request(
                f"http://localhost:{HTTP_PORT}/v1/test",
                headers={
                    "Host": "auth-test.local",
                    "Authorization": "Bearer key-for-fallback",
                },
            )
            assert status == 200, f"Expected 200, got {status}"
            assert data["server_id"] == "fallback", f"Expected fallback, got {data['server_id']}"
            print(f"  -> Routed to: {data['server_id']} ✓")

            print("\n=== All tests passed! ===\n")

        finally:
            # Cleanup
            proxy_proc.terminate()
            try:
                proxy_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()

            server1.shutdown()
            server2.shutdown()
            server_fallback.shutdown()


if __name__ == "__main__":
    test_auth_selects_correct_provider()
