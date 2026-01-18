"""
E2E tests for health check and authentication error handling.

Tests the scenario where a provider is disabled due to health check failure,
and verifies that requests with the disabled provider's API key return 404
instead of 401.

This test file is self-contained and manages its own openproxy instance and
echo servers.
"""

import httpx
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# Configuration
PROXY_HTTPS_PORT = 18443
PROXY_HTTP_PORT = 18080
HEALTHY_ECHO_PORT = 19002
UNHEALTHY_ECHO_PORT = 19003  # This port will NOT have a server running

HEALTHY_API_KEY = "sk-healthy-key"
UNHEALTHY_API_KEY = "sk-unhealthy-key"
INVALID_API_KEY = "sk-invalid-key-12345"

# Test host that both providers will match
TEST_HOST = f"healthcheck-test.local:{PROXY_HTTPS_PORT}"
TEST_HOST_HTTP = f"healthcheck-test.local:{PROXY_HTTP_PORT}"


def create_config(cert_file: str, key_file: str) -> str:
    """Generate a config file for the test."""
    config = f"""
cert_file: {cert_file}
private_key_file: {key_file}
https_port: {PROXY_HTTPS_PORT}
http_port: {PROXY_HTTP_PORT}

health_check:
  enabled: true
  interval: 2

providers:
  # Healthy provider - echo server will be running on this port
  - type: openai
    host: {TEST_HOST}
    endpoint: localhost
    port: {HEALTHY_ECHO_PORT}
    tls: false
    api_key: sk-upstream-healthy
    auth_keys:
      - {HEALTHY_API_KEY}

  # Unhealthy provider - NO echo server will be running on this port
  - type: openai
    host: {TEST_HOST}
    endpoint: localhost
    port: {UNHEALTHY_ECHO_PORT}
    tls: false
    api_key: sk-upstream-unhealthy
    auth_keys:
      - {UNHEALTHY_API_KEY}

  # HTTP providers (same setup)
  - type: openai
    host: {TEST_HOST_HTTP}
    endpoint: localhost
    port: {HEALTHY_ECHO_PORT}
    tls: false
    api_key: sk-upstream-healthy
    auth_keys:
      - {HEALTHY_API_KEY}

  - type: openai
    host: {TEST_HOST_HTTP}
    endpoint: localhost
    port: {UNHEALTHY_ECHO_PORT}
    tls: false
    api_key: sk-upstream-unhealthy
    auth_keys:
      - {UNHEALTHY_API_KEY}
"""
    return config


def generate_self_signed_cert(tmpdir: str) -> tuple[str, str]:
    """Generate a self-signed certificate for testing."""
    cert_file = os.path.join(tmpdir, "cert.pem")
    key_file = os.path.join(tmpdir, "key.pem")

    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"
    ], check=True, capture_output=True)

    return cert_file, key_file


def start_echo_server(port: int, server_id: str) -> subprocess.Popen:
    """Start an echo server that returns its server_id."""
    server_code = f'''
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps({{"server_id": "{server_id}", "path": self.path}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.do_GET()

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", {port}), Handler).serve_forever()
'''
    return subprocess.Popen([sys.executable, "-c", server_code])


def find_openproxy_binary() -> str:
    """Find the openproxy binary."""
    # Try environment variable first
    if "OPENPROXY_BINARY" in os.environ:
        return os.environ["OPENPROXY_BINARY"]

    # Try common locations
    candidates = [
        Path(__file__).parent.parent / "target" / "release" / "openproxy",
        Path(__file__).parent.parent / "target" / "debug" / "openproxy",
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise FileNotFoundError("Could not find openproxy binary")


def start_openproxy(config_file: str, log_file: str) -> subprocess.Popen:
    """Start the openproxy server with output redirected to a log file."""
    binary = find_openproxy_binary()
    log_handle = open(log_file, "w")
    return subprocess.Popen(
        [binary, "start", "-c", config_file],
        stdout=log_handle,
        stderr=log_handle,
    ), log_handle


def wait_for_server(port: int, timeout: float = 10.0, ssl: bool = False) -> bool:
    """Wait for a server to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with httpx.Client(verify=False, timeout=1.0) as client:
                scheme = "https" if ssl else "http"
                client.get(f"{scheme}://localhost:{port}/")
            return True
        except Exception:
            time.sleep(0.1)
    return False


def wait_for_health_check_failure(timeout: float = 15.0):
    """Wait for health check to detect the unhealthy provider."""
    # Health check interval is 2 seconds, so we wait a bit longer
    print(f"  Waiting for health check to detect unhealthy provider...")
    time.sleep(timeout)
    print(f"  Health check wait complete")


def test_health_check_auth_http1(cert_file: str):
    """Test health check + auth error handling for HTTP/1.1."""
    print(f"\n{'='*50}")
    print("Testing HTTP/1.1 health check auth error handling")
    print('='*50)

    with httpx.Client(
        base_url=f"https://localhost:{PROXY_HTTPS_PORT}",
        http2=False,
        verify=cert_file,
        timeout=10.0,
    ) as client:
        # Test 1: Healthy provider's key should succeed (200)
        print("  Test 1: Healthy provider key -> 200")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {HEALTHY_API_KEY}",
                "Host": TEST_HOST,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert "server_id" in resp.text, f"Expected server_id in response: {resp.text}"
        print("    PASSED")

        # Test 2: Unhealthy provider's key should return 404 (provider disabled)
        print("  Test 2: Unhealthy provider key -> 404")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {UNHEALTHY_API_KEY}",
                "Host": TEST_HOST,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
        assert "no provider found" in resp.text.lower(), f"Expected 'no provider found' in body: {resp.text}"
        print("    PASSED")

        # Test 3: Invalid key should return 401 (auth failed)
        print("  Test 3: Invalid key -> 401")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {INVALID_API_KEY}",
                "Host": TEST_HOST,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
        assert "authentication failed" in resp.text.lower(), f"Expected 'authentication failed' in body: {resp.text}"
        print("    PASSED")

    print("\u2713 HTTP/1.1 health check auth tests passed!")


def test_health_check_auth_http2(cert_file: str):
    """Test health check + auth error handling for HTTP/2."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 health check auth error handling")
    print('='*50)

    with httpx.Client(
        base_url=f"https://localhost:{PROXY_HTTPS_PORT}",
        http2=True,
        verify=cert_file,
        timeout=10.0,
    ) as client:
        # Test 1: Healthy provider's key should succeed (200)
        print("  Test 1: Healthy provider key -> 200")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {HEALTHY_API_KEY}",
                "Host": TEST_HOST,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    HTTP Version: {resp.http_version}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert "server_id" in resp.text, f"Expected server_id in response: {resp.text}"
        print("    PASSED")

        # Test 2: Unhealthy provider's key should return 404 (provider disabled)
        print("  Test 2: Unhealthy provider key -> 404")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {UNHEALTHY_API_KEY}",
                "Host": TEST_HOST,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    HTTP Version: {resp.http_version}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
        assert "no provider found" in resp.text.lower(), f"Expected 'no provider found' in body: {resp.text}"
        print("    PASSED")

        # Test 3: Invalid key should return 401 (auth failed)
        print("  Test 3: Invalid key -> 401")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {INVALID_API_KEY}",
                "Host": TEST_HOST,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    HTTP Version: {resp.http_version}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
        assert "authentication failed" in resp.text.lower(), f"Expected 'authentication failed' in body: {resp.text}"
        print("    PASSED")

    print("\u2713 HTTP/2 health check auth tests passed!")


def test_health_check_auth_plain_http():
    """Test health check + auth error handling for plain HTTP."""
    print(f"\n{'='*50}")
    print("Testing plain HTTP health check auth error handling")
    print('='*50)

    with httpx.Client(
        base_url=f"http://localhost:{PROXY_HTTP_PORT}",
        timeout=10.0,
    ) as client:
        # Test 1: Healthy provider's key should succeed (200)
        print("  Test 1: Healthy provider key -> 200")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {HEALTHY_API_KEY}",
                "Host": TEST_HOST_HTTP,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert "server_id" in resp.text, f"Expected server_id in response: {resp.text}"
        print("    PASSED")

        # Test 2: Unhealthy provider's key should return 404 (provider disabled)
        print("  Test 2: Unhealthy provider key -> 404")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {UNHEALTHY_API_KEY}",
                "Host": TEST_HOST_HTTP,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
        assert "no provider found" in resp.text.lower(), f"Expected 'no provider found' in body: {resp.text}"
        print("    PASSED")

        # Test 3: Invalid key should return 401 (auth failed)
        print("  Test 3: Invalid key -> 401")
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {INVALID_API_KEY}",
                "Host": TEST_HOST_HTTP,
            },
        )
        print(f"    Status: {resp.status_code}")
        print(f"    Body: {resp.text[:100] if resp.text else '(empty)'}")
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
        assert "authentication failed" in resp.text.lower(), f"Expected 'authentication failed' in body: {resp.text}"
        print("    PASSED")

    print("\u2713 Plain HTTP health check auth tests passed!")


def main():
    """Main test runner."""
    processes = []
    file_handles = []
    tmpdir = tempfile.mkdtemp()
    proxy_log_file = os.path.join(tmpdir, "proxy.log")

    try:
        print("Setting up test environment...")

        # Generate certificates
        print("  Generating self-signed certificate...")
        cert_file, key_file = generate_self_signed_cert(tmpdir)

        # Create config
        print("  Creating config file...")
        config_content = create_config(cert_file, key_file)
        config_file = os.path.join(tmpdir, "config.yml")
        with open(config_file, "w") as f:
            f.write(config_content)
        print(f"  Config written to {config_file}")

        # Start only the HEALTHY echo server (do NOT start the unhealthy one)
        print(f"  Starting healthy echo server on port {HEALTHY_ECHO_PORT}...")
        echo_proc = start_echo_server(HEALTHY_ECHO_PORT, "healthy")
        processes.append(echo_proc)
        time.sleep(1)

        # Verify echo server is running
        if not wait_for_server(HEALTHY_ECHO_PORT, timeout=5.0, ssl=False):
            raise RuntimeError(f"Echo server on port {HEALTHY_ECHO_PORT} did not start")
        print(f"  Echo server is ready")

        # Start openproxy
        print("  Starting openproxy...")
        proxy_proc, log_handle = start_openproxy(config_file, proxy_log_file)
        processes.append(proxy_proc)
        file_handles.append(log_handle)

        # Wait for proxy to be ready
        if not wait_for_server(PROXY_HTTPS_PORT, timeout=10.0, ssl=True):
            # Check if proxy crashed and print log file
            if proxy_proc.poll() is not None:
                log_handle.flush()
                with open(proxy_log_file, "r") as f:
                    print(f"  Proxy log:\n{f.read()}")
            raise RuntimeError(f"Proxy on port {PROXY_HTTPS_PORT} did not start")
        print(f"  Proxy is ready")

        # Wait for health check to detect the unhealthy provider
        wait_for_health_check_failure(timeout=8.0)

        # Run tests
        test_health_check_auth_http1(cert_file)
        test_health_check_auth_http2(cert_file)
        test_health_check_auth_plain_http()

        print("\n" + "="*50)
        print("\u2713 All health check auth tests passed!")
        print("="*50)

    finally:
        # Cleanup
        print("\nCleaning up...")
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

        # Close file handles
        for fh in file_handles:
            try:
                fh.close()
            except Exception:
                pass

        # Clean up temp directory
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
        print("Cleanup complete")


if __name__ == "__main__":
    main()
