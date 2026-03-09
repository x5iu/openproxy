"""
E2E tests for strict HTTP/1.1 request parsing.

These tests verify that malformed framing headers are rejected with 400 before
the request reaches the upstream server:
1. Duplicate Content-Length
2. Duplicate Transfer-Encoding
3. Content-Length combined with mixed-case Transfer-Encoding: Chunked
"""

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


PROXY_HTTP_PORT = 28081
UPSTREAM_PORT = 29009
TEST_HOST = f"strict-http.local:{PROXY_HTTP_PORT}"


class CountingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    request_count = 0

    def do_GET(self):
        type(self).request_count += 1
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).request_count += 1
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
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


def start_upstream_server() -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer(("127.0.0.1", UPSTREAM_PORT), CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    wait_for_port(UPSTREAM_PORT)
    return server, thread


def create_config(config_path: str) -> None:
    config = f"""
http_port: {PROXY_HTTP_PORT}

providers:
  - type: openai
    host: {TEST_HOST}
    endpoint: localhost
    port: {UPSTREAM_PORT}
    tls: false
"""
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(config)


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
            if b"\r\n\r\n" in response:
                break
    return response.decode("utf-8", errors="replace")


def assert_bad_request(name: str, request: bytes) -> None:
    before = CountingHandler.request_count
    response = send_raw_request(request)
    print(f"\n{name}")
    print(response)
    assert "400 Bad Request" in response, f"{name}: expected 400, got {response!r}"
    time.sleep(0.2)
    assert CountingHandler.request_count == before, (
        f"{name}: upstream should not receive the request"
    )


def main() -> None:
    server, _thread = start_upstream_server()

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = os.path.join(tmpdir, "config.yml")
        log_file = os.path.join(tmpdir, "openproxy.log")
        create_config(config_file)
        proxy, log_handle = start_openproxy(config_file, log_file)

        try:
            assert_bad_request(
                "Duplicate Content-Length should be rejected",
                (
                    f"POST /v1/test HTTP/1.1\r\n"
                    f"Host: {TEST_HOST}\r\n"
                    "Content-Length: 1\r\n"
                    "Content-Length: 1\r\n"
                    "\r\n"
                    "a"
                ).encode("utf-8"),
            )

            assert_bad_request(
                "Duplicate Transfer-Encoding should be rejected",
                (
                    f"POST /v1/test HTTP/1.1\r\n"
                    f"Host: {TEST_HOST}\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "0\r\n\r\n"
                ).encode("utf-8"),
            )

            assert_bad_request(
                "Chunked Transfer-Encoding without space should be rejected with Content-Length",
                (
                    f"POST /v1/test HTTP/1.1\r\n"
                    f"Host: {TEST_HOST}\r\n"
                    "Content-Length:5\r\n"
                    "Transfer-Encoding:chunked\r\n"
                    "\r\n"
                    "0\r\n\r\n"
                ).encode("utf-8"),
            )

            assert_bad_request(
                "Mixed-case Transfer-Encoding with Content-Length should be rejected",
                (
                    f"POST /v1/test HTTP/1.1\r\n"
                    f"Host: {TEST_HOST}\r\n"
                    "Content-Length: 5\r\n"
                    "Transfer-Encoding: Chunked\r\n"
                    "\r\n"
                    "0\r\n\r\n"
                ).encode("utf-8"),
            )

            print("\nAll strict HTTP parsing E2E tests passed.")
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
