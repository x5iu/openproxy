"""
E2E test for filtering duplicate extra headers that are transformed upstream.

This verifies that when a client sends multiple anthropic-beta headers to an
Anthropic OAuth provider over HTTP/1.1, the proxy strips all client copies and
forwards a single transformed anthropic-beta header upstream.
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


PROXY_HTTP_PORT = 28084
UPSTREAM_PORT = 29013
TEST_HOST = f"duplicate-extra.local:{PROXY_HTTP_PORT}"
AUTH_KEY = "duplicate-extra-auth"


class EchoHeadersHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        headers_multi = {}
        for key in self.headers.keys():
            lower = key.lower()
            headers_multi.setdefault(lower, []).extend(self.headers.get_all(key) or [])

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


def create_config(config_path: str) -> None:
    config = f"""
http_port: {PROXY_HTTP_PORT}
auth_keys:
  - {AUTH_KEY}

providers:
  - type: anthropic
    host: {TEST_HOST}
    endpoint: localhost
    port: {UPSTREAM_PORT}
    tls: false
    api_key: '$(printf oauth-token)'
"""
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(config)


def start_upstream_server() -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer(("127.0.0.1", UPSTREAM_PORT), EchoHeadersHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    wait_for_port(UPSTREAM_PORT)
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
    return process, log_handle


def send_raw_request(request: bytes) -> str:
    with socket.create_connection(("127.0.0.1", PROXY_HTTP_PORT), timeout=10) as sock:
        sock.settimeout(2)
        sock.sendall(request)
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
    return response.decode("utf-8", errors="replace")


def main() -> None:
    server, _thread = start_upstream_server()

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = os.path.join(tmpdir, "config.yml")
        log_file = os.path.join(tmpdir, "openproxy.log")
        create_config(config_file)
        proxy, log_handle = start_openproxy(config_file, log_file)

        try:
            print("\nTesting duplicate transformed extra header filtering")
            response = send_raw_request(
                (
                    f"GET /v1/messages HTTP/1.1\r\n"
                    f"Host: {TEST_HOST}\r\n"
                    f"Authorization: Bearer {AUTH_KEY}\r\n"
                    "anthropic-beta: streaming-2024-01-01\r\n"
                    "anthropic-beta: tools-2024-04-04\r\n"
                    "\r\n"
                ).encode("utf-8")
            )
            print(response)
            assert "200 OK" in response, response

            body = response.split("\r\n\r\n", 1)[1]
            data = json.loads(body)
            headers = data["headers"]
            print(json.dumps(data, indent=2))

            assert headers.get("authorization") == ["Bearer oauth-token"], headers
            assert headers.get("anthropic-beta") == [
                "streaming-2024-01-01, tools-2024-04-04, oauth-2025-04-20"
            ], headers

            print("\nDuplicate extra header filtering E2E test passed.")
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=5)
            log_handle.close()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Test failed: {exc}", file=sys.stderr)
        raise
