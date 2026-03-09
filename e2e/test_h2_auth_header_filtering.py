"""
E2E test for HTTP/2 auth header filtering across all matching providers.

This verifies that when multiple providers match the same host/path and the selected
provider uses one auth scheme, client auth headers belonging to the other matching
providers are still stripped before forwarding upstream.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx


PROXY_HTTPS_PORT = 28446
PROXY_HTTP_PORT = 28083
HTTP_ECHO_PORT = 29012

AUTH_KEY = "shared-auth-key"
OPENAI_PROVIDER_API_KEY = "sk-openai-upstream-key"
CLIENT_X_API_KEY = AUTH_KEY
TEST_HOST = f"shared-auth.local:{PROXY_HTTPS_PORT}"


class EchoHeadersHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        headers_multi = {}
        for key, value in self.headers.items():
            headers_multi.setdefault(key.lower(), []).append(value)

        body = json.dumps(
            {
                "headers": headers_multi,
                "path": self.path,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def find_openproxy_binary() -> str:
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


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for port {port}")


def generate_self_signed_cert(tmpdir: str) -> tuple[str, str]:
    cert_file = os.path.join(tmpdir, "cert.pem")
    key_file = os.path.join(tmpdir, "key.pem")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_file,
            "-out",
            cert_file,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return cert_file, key_file


def create_config(config_path: str, cert_file: str, key_file: str) -> None:
    config = f"""
cert_file: {cert_file}
private_key_file: {key_file}
https_port: {PROXY_HTTPS_PORT}
http_port: {PROXY_HTTP_PORT}
auth_keys:
  - {AUTH_KEY}

providers:
  - type: openai
    host: {TEST_HOST}
    endpoint: localhost
    port: {HTTP_ECHO_PORT}
    tls: false
    api_key: {OPENAI_PROVIDER_API_KEY}
    priority: 10
  - type: anthropic
    host: {TEST_HOST}
    endpoint: localhost
    port: {HTTP_ECHO_PORT}
    tls: false
    api_key: anthropic-upstream-key
    priority: 0
"""
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(config)


def start_http_echo_server() -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer(("127.0.0.1", HTTP_ECHO_PORT), EchoHeadersHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    wait_for_port(HTTP_ECHO_PORT)
    return server, thread


def start_openproxy(config_file: str, log_file: str):
    binary = find_openproxy_binary()
    log_handle = open(log_file, "w", encoding="utf-8")
    process = subprocess.Popen(
        [binary, "start", "-c", config_file],
        stdout=log_handle,
        stderr=log_handle,
    )
    wait_for_port(PROXY_HTTP_PORT)
    wait_for_port(PROXY_HTTPS_PORT)
    return process, log_handle


def main() -> None:
    http_server, _thread = start_http_echo_server()

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file, key_file = generate_self_signed_cert(tmpdir)
        config_file = os.path.join(tmpdir, "config.yml")
        log_file = os.path.join(tmpdir, "openproxy.log")
        create_config(config_file, cert_file, key_file)
        proxy, log_handle = start_openproxy(config_file, log_file)

        try:
            print("\nTesting HTTP/2 filtering across all matching providers")
            with httpx.Client(verify=cert_file, http2=True, timeout=30) as client:
                response = client.get(
                    f"https://localhost:{PROXY_HTTPS_PORT}/v1/test",
                    headers={
                        "Host": TEST_HOST,
                        "Authorization": f"Bearer {AUTH_KEY}",
                        "X-API-Key": CLIENT_X_API_KEY,
                    },
                )

            print(f"  Status: {response.status_code}")
            print(f"  HTTP version: {response.http_version}")
            assert response.status_code == 200
            assert response.http_version == "HTTP/2"

            data = response.json()
            headers = data["headers"]
            print(json.dumps(data, indent=2))

            assert headers.get("authorization") == [f"Bearer {OPENAI_PROVIDER_API_KEY}"], headers
            assert headers.get("x-api-key") is None, headers
            assert headers.get("proxy-authorization") is None, headers

            print("\nHTTP/2 auth header filtering E2E test passed.")
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=5)
            log_handle.close()
            http_server.shutdown()
            http_server.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Test failed: {exc}", file=sys.stderr)
        raise
