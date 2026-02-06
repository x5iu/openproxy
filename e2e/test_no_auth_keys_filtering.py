"""
E2E tests for auth header filtering when provider has api_key but NO auth_keys.

When a provider has an api_key configured but no auth_keys (and no global
auth_keys), the proxy should:
1. NOT forward the client's Authorization header to upstream
2. Inject the provider's api_key as the Authorization header instead

This tests a bug where HTTP/1.1 would forward BOTH the client's auth header
AND the provider's auth header, causing duplicate Authorization headers upstream.

This test file is self-contained and manages its own openproxy instance and
echo server. The echo server preserves duplicate headers so we can detect
when both client and provider Authorization headers are sent.
"""

import httpx
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# Configuration
PROXY_HTTPS_PORT = 28443
PROXY_HTTP_PORT = 28080
ECHO_PORT = 29008

PROVIDER_API_KEY = "sk-provider-only-key"
CLIENT_AUTH = "Bearer client-should-be-filtered"

TEST_HOST_HTTPS = f"no-auth-keys.local:{PROXY_HTTPS_PORT}"
TEST_HOST_HTTP = f"no-auth-keys.local:{PROXY_HTTP_PORT}"


def create_config(cert_file: str, key_file: str) -> str:
    """Generate a config file with NO global auth_keys."""
    return f"""
cert_file: {cert_file}
private_key_file: {key_file}
https_port: {PROXY_HTTPS_PORT}
http_port: {PROXY_HTTP_PORT}

providers:
  # Provider with api_key but NO auth_keys - the bug scenario
  - type: openai
    host: {TEST_HOST_HTTPS}
    endpoint: localhost
    port: {ECHO_PORT}
    tls: false
    api_key: {PROVIDER_API_KEY}
  - type: openai
    host: {TEST_HOST_HTTP}
    endpoint: localhost
    port: {ECHO_PORT}
    tls: false
    api_key: {PROVIDER_API_KEY}
"""


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


def start_echo_server(port: int) -> subprocess.Popen:
    """Start an echo server that returns received headers as lists to detect duplicates."""
    server_code = f'''
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class EchoHeadersHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send_response(self):
        # Preserve duplicate headers by using lists as values
        headers_multi = {{}}
        for k, v in self.headers.items():
            key = k.lower()
            if key not in headers_multi:
                headers_multi[key] = []
            headers_multi[key].append(v)
        response = {{"headers": headers_multi, "path": self.path}}
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self): self._send_response()
    def do_POST(self): self._send_response()
    def log_message(self, *args): pass

HTTPServer(("127.0.0.1", {port}), EchoHeadersHandler).serve_forever()
'''
    return subprocess.Popen([sys.executable, "-c", server_code])


def find_openproxy_binary() -> str:
    """Find the openproxy binary."""
    if "OPENPROXY_BINARY" in os.environ:
        return os.environ["OPENPROXY_BINARY"]
    candidates = [
        Path(__file__).parent.parent / "target" / "release" / "openproxy",
        Path(__file__).parent.parent / "target" / "debug" / "openproxy",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise FileNotFoundError("Could not find openproxy binary")


def start_openproxy(config_file: str, log_file: str):
    """Start the openproxy server."""
    binary = find_openproxy_binary()
    log_handle = open(log_file, "w")
    return subprocess.Popen(
        [binary, "start", "-c", config_file],
        stdout=log_handle,
        stderr=log_handle,
    ), log_handle


def wait_for_server(port: int, timeout: float = 10.0, use_ssl: bool = False) -> bool:
    """Wait for a server to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with httpx.Client(verify=False, timeout=1.0) as client:
                scheme = "https" if use_ssl else "http"
                client.get(f"{scheme}://localhost:{port}/")
            return True
        except Exception:
            time.sleep(0.1)
    return False


def assert_single_provider_auth(data: dict, test_name: str):
    """Assert that upstream received exactly one Authorization header with the provider's key."""
    auth_values = data["headers"].get("authorization", [])
    print(f"  Upstream received Authorization values: {auth_values}")

    assert len(auth_values) == 1, (
        f"[{test_name}] Expected exactly 1 Authorization header, "
        f"got {len(auth_values)}: {auth_values}"
    )
    assert auth_values[0] == f"Bearer {PROVIDER_API_KEY}", (
        f"[{test_name}] Expected provider key 'Bearer {PROVIDER_API_KEY}', "
        f"but got '{auth_values[0]}'"
    )


def test_http11_plain_filters_client_auth():
    """HTTP/1.1 (plain HTTP): client auth should be replaced by provider api_key."""
    print(f"\n{'='*60}")
    print("Test 1: HTTP/1.1 (plain HTTP) - client auth should be filtered")
    print("=" * 60)

    with httpx.Client(http2=False, timeout=30) as client:
        resp = client.get(
            f"http://localhost:{PROXY_HTTP_PORT}/v1/test",
            headers={
                "Host": TEST_HOST_HTTP,
                "Authorization": CLIENT_AUTH,
            },
        )

        print(f"  Status: {resp.status_code}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        print(f"  Response: {json.dumps(data, indent=2)}")
        assert_single_provider_auth(data, "HTTP/1.1 plain")

    print("  PASSED")


def test_http11_tls_filters_client_auth(cert_file: str):
    """HTTP/1.1 over TLS: client auth should be replaced by provider api_key."""
    print(f"\n{'='*60}")
    print("Test 2: HTTP/1.1 (HTTPS) - client auth should be filtered")
    print("=" * 60)

    with httpx.Client(verify=cert_file, http2=False, timeout=30) as client:
        resp = client.get(
            f"https://localhost:{PROXY_HTTPS_PORT}/v1/test",
            headers={
                "Host": TEST_HOST_HTTPS,
                "Authorization": CLIENT_AUTH,
            },
        )

        print(f"  Status: {resp.status_code}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        print(f"  Response: {json.dumps(data, indent=2)}")
        assert_single_provider_auth(data, "HTTP/1.1 TLS")

    print("  PASSED")


def test_h2_filters_client_auth(cert_file: str):
    """HTTP/2: client auth should be replaced by provider api_key."""
    print(f"\n{'='*60}")
    print("Test 3: HTTP/2 - client auth should be filtered")
    print("=" * 60)

    with httpx.Client(verify=cert_file, http2=True, timeout=30) as client:
        resp = client.get(
            f"https://localhost:{PROXY_HTTPS_PORT}/v1/test",
            headers={
                "Host": TEST_HOST_HTTPS,
                "Authorization": CLIENT_AUTH,
            },
        )

        print(f"  Status: {resp.status_code}")
        print(f"  HTTP Version: {resp.http_version}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        print(f"  Response: {json.dumps(data, indent=2)}")
        assert_single_provider_auth(data, "HTTP/2")

    print("  PASSED")


def test_no_client_auth_still_injects_provider_key():
    """When client sends no auth, upstream should still get provider's api_key."""
    print(f"\n{'='*60}")
    print("Test 4: No client auth - provider key should still be injected")
    print("=" * 60)

    with httpx.Client(http2=False, timeout=30) as client:
        resp = client.get(
            f"http://localhost:{PROXY_HTTP_PORT}/v1/test",
            headers={
                "Host": TEST_HOST_HTTP,
            },
        )

        print(f"  Status: {resp.status_code}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        print(f"  Response: {json.dumps(data, indent=2)}")
        assert_single_provider_auth(data, "No client auth")

    print("  PASSED")


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

        # Start echo server
        print(f"  Starting echo server on port {ECHO_PORT}...")
        echo_proc = start_echo_server(ECHO_PORT)
        processes.append(echo_proc)
        time.sleep(1)

        if not wait_for_server(ECHO_PORT, timeout=5.0):
            raise RuntimeError(f"Echo server on port {ECHO_PORT} did not start")
        print("  Echo server is ready")

        # Start openproxy
        print("  Starting openproxy...")
        proxy_proc, log_handle = start_openproxy(config_file, proxy_log_file)
        processes.append(proxy_proc)
        file_handles.append(log_handle)

        if not wait_for_server(PROXY_HTTPS_PORT, timeout=10.0, use_ssl=True):
            if proxy_proc.poll() is not None:
                log_handle.flush()
                with open(proxy_log_file, "r") as f:
                    print(f"  Proxy log:\n{f.read()}")
            raise RuntimeError(f"Proxy on port {PROXY_HTTPS_PORT} did not start")
        print("  Proxy is ready")

        # Run tests
        test_http11_plain_filters_client_auth()
        test_http11_tls_filters_client_auth(cert_file)
        test_h2_filters_client_auth(cert_file)
        test_no_client_auth_still_injects_provider_key()

        print("\n" + "=" * 60)
        print("All no-auth-keys filtering tests passed!")
        print("=" * 60)

    finally:
        print("\nCleaning up...")
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

        for fh in file_handles:
            try:
                fh.close()
            except Exception:
                pass

        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
        print("Cleanup complete")


if __name__ == "__main__":
    main()
