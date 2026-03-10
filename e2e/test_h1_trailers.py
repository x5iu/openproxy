"""
E2E test for global trailer ignoring on HTTP/1.1 proxy paths.

This test is self-contained:
- starts a raw HTTP/1.1 upstream server
- starts a dedicated OpenProxy instance in HTTP-only mode
- sends a chunked HTTP/1.1 request with TE/Trailer headers and request trailers
- verifies the upstream request body is preserved but trailer metadata is stripped
- sends a second HTTP/1.1 request and has the upstream reply with chunked response trailers
- verifies the downstream client sees the response body without trailer metadata
"""

import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


PROXY_AUTH_KEY = "h1-trailer-auth-key"
UPSTREAM_API_KEY = "sk-upstream-trailer-key"
REQUEST_BODY = b"abcdefghij"
RESPONSE_BODY = b"hello"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return sock.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.1)
    return False


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


def start_openproxy(config_path: str, log_path: str):
    binary = find_openproxy_binary()
    log_handle = open(log_path, "w")
    process = subprocess.Popen(
        [binary, "start", "-c", config_path],
        stdout=log_handle,
        stderr=log_handle,
    )
    return process, log_handle


def stop_process(process: subprocess.Popen):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


class BufferedSocketReader:
    def __init__(self, conn: socket.socket):
        self.conn = conn
        self.buffer = bytearray()

    def _fill(self):
        chunk = self.conn.recv(4096)
        if not chunk:
            raise EOFError("unexpected EOF while reading HTTP message")
        self.buffer.extend(chunk)

    def read_until(self, marker: bytes) -> bytes:
        while True:
            idx = self.buffer.find(marker)
            if idx != -1:
                end = idx + len(marker)
                data = bytes(self.buffer[:end])
                del self.buffer[:end]
                return data
            self._fill()

    def read_line(self) -> bytes:
        return self.read_until(b"\r\n")

    def read_exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            self._fill()
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data


def parse_head(head: bytes) -> tuple[str, dict[str, str]]:
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    first_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return first_line, headers


def read_chunked_body(reader: BufferedSocketReader) -> tuple[bytes, bytes]:
    decoded = bytearray()
    raw = bytearray()

    while True:
        line = reader.read_line()
        raw.extend(line)
        size_text = line[:-2].split(b";", 1)[0].strip()
        size = int(size_text, 16)
        if size == 0:
            while True:
                trailer_line = reader.read_line()
                raw.extend(trailer_line)
                if trailer_line == b"\r\n":
                    return bytes(decoded), bytes(raw)
        chunk = reader.read_exact(size)
        decoded.extend(chunk)
        raw.extend(chunk)
        raw.extend(reader.read_exact(2))


def read_http_response(sock: socket.socket) -> dict:
    reader = BufferedSocketReader(sock)
    head = reader.read_until(b"\r\n\r\n")
    status_line, headers = parse_head(head)

    body = b""
    raw_body = b""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body, raw_body = read_chunked_body(reader)
    elif "content-length" in headers:
        body = reader.read_exact(int(headers["content-length"]))
        raw_body = body

    return {
        "status_line": status_line,
        "headers": headers,
        "body": body,
        "raw_body": raw_body,
    }


def send_raw_request(port: int, request: bytes) -> dict:
    with socket.create_connection(("127.0.0.1", port), timeout=10.0) as sock:
        sock.settimeout(5.0)
        sock.sendall(request)
        return read_http_response(sock)


def start_capture_server(port: int, capture: dict) -> tuple[threading.Thread, threading.Event]:
    ready = threading.Event()

    def run():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(5)
        ready.set()

        handled = 0
        try:
            while handled < 2:
                conn, _ = server.accept()
                handled += 1
                with conn:
                    reader = BufferedSocketReader(conn)
                    head = reader.read_until(b"\r\n\r\n")
                    request_line, headers = parse_head(head)

                    body = b""
                    raw_body = b""
                    if headers.get("transfer-encoding", "").lower() == "chunked":
                        body, raw_body = read_chunked_body(reader)
                    elif "content-length" in headers:
                        body = reader.read_exact(int(headers["content-length"]))
                        raw_body = body

                    if request_line == "POST /capture-request HTTP/1.1":
                        capture["request_test"] = {
                            "request_line": request_line,
                            "headers": headers,
                            "body": body,
                            "raw_body": raw_body,
                        }
                        response_body = json.dumps({"ok": True}).encode("utf-8")
                        response = (
                            b"HTTP/1.1 200 OK\r\n"
                            + b"Content-Type: application/json\r\n"
                            + f"Content-Length: {len(response_body)}\r\n".encode("ascii")
                            + b"Connection: close\r\n\r\n"
                            + response_body
                        )
                        conn.sendall(response)
                    elif request_line == "GET /capture-response HTTP/1.1":
                        capture["response_test_request"] = {
                            "request_line": request_line,
                            "headers": headers,
                            "body": body,
                            "raw_body": raw_body,
                        }
                        response = (
                            b"HTTP/1.1 200 OK\r\n"
                            + b"Transfer-Encoding: chunked\r\n"
                            + b"Trailer: x-checksum\r\n"
                            + b"Connection: close\r\n\r\n"
                            + b"5\r\nhello\r\n0\r\nx-checksum: resp-abc123\r\n\r\n"
                        )
                        conn.sendall(response)
                    else:
                        conn.sendall(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
        finally:
            server.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, ready


def create_config(proxy_port: int, upstream_port: int) -> str:
    authority = f"trailer-test.local:{proxy_port}"
    return f"""
http_port: {proxy_port}
auth_keys:
  - {PROXY_AUTH_KEY}
providers:
  - type: openai
    host: {authority}
    endpoint: 127.0.0.1
    port: {upstream_port}
    tls: false
    api_key: {UPSTREAM_API_KEY}
"""


def test_h1_request_and_response_trailers_are_ignored():
    print("\n" + "=" * 60)
    print("Testing HTTP/1.1 trailer ignoring")
    print("=" * 60)

    proxy_port = find_free_port()
    upstream_port = find_free_port()
    authority = f"trailer-test.local:{proxy_port}"
    capture: dict = {}

    capture_thread, ready = start_capture_server(upstream_port, capture)
    if not ready.wait(timeout=5):
        raise RuntimeError("capture server failed to start")

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.yml")
        log_path = os.path.join(tmpdir, "openproxy.log")
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(create_config(proxy_port, upstream_port))

        proxy_process, proxy_log = start_openproxy(config_path, log_path)
        failed = False
        try:
            if not wait_for_port("127.0.0.1", proxy_port, timeout=20):
                raise RuntimeError("openproxy HTTP port did not open in time")

            request = (
                f"POST /capture-request HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                f"Authorization: Bearer {PROXY_AUTH_KEY}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"TE: trailers\r\n"
                f"Trailer: x-checksum\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"a\r\nabcdefghij\r\n0\r\nx-checksum: req-abc123\r\n\r\n"
            ).encode("utf-8")
            response = send_raw_request(proxy_port, request)
            print("Request-trailer response:", response["status_line"])
            assert response["status_line"].startswith("HTTP/1.1 200"), response

            upstream_request = capture["request_test"]
            print("Captured upstream request headers:", upstream_request["headers"])
            assert upstream_request["request_line"] == "POST /capture-request HTTP/1.1"
            assert upstream_request["headers"].get("authorization") == f"Bearer {UPSTREAM_API_KEY}"
            assert "te" not in upstream_request["headers"], upstream_request
            assert "trailer" not in upstream_request["headers"], upstream_request
            assert upstream_request["body"] == REQUEST_BODY
            assert upstream_request["raw_body"] == b"a\r\nabcdefghij\r\n0\r\n\r\n"

            response_request = (
                f"GET /capture-response HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                f"Authorization: Bearer {PROXY_AUTH_KEY}\r\n"
                f"TE: trailers\r\n"
                f"Trailer: x-checksum\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("utf-8")
            response = send_raw_request(proxy_port, response_request)
            print("Response-trailer response:", response["status_line"])
            print("Proxy response headers:", response["headers"])
            assert response["status_line"].startswith("HTTP/1.1 200"), response
            assert "trailer" not in response["headers"], response
            assert response["body"] == RESPONSE_BODY
            assert response["raw_body"] == b"5\r\nhello\r\n0\r\n\r\n"

            upstream_response_request = capture["response_test_request"]
            assert upstream_response_request["request_line"] == "GET /capture-response HTTP/1.1"
            assert upstream_response_request["headers"].get("authorization") == (
                f"Bearer {UPSTREAM_API_KEY}"
            )
            assert "te" not in upstream_response_request["headers"], upstream_response_request
            assert "trailer" not in upstream_response_request["headers"], upstream_response_request

            capture_thread.join(timeout=5)
            if capture_thread.is_alive():
                raise AssertionError("capture server thread did not finish")

            print("✓ HTTP/1.1 trailer ignoring test passed")
        except Exception:
            failed = True
            raise
        finally:
            stop_process(proxy_process)
            proxy_log.close()
            if failed and os.path.exists(log_path):
                with open(log_path, "r", encoding="utf-8") as f:
                    log_content = f.read().strip()
                    if log_content:
                        print("\nOpenProxy log output:")
                        print(log_content)


if __name__ == "__main__":
    test_h1_request_and_response_trailers_are_ignored()
