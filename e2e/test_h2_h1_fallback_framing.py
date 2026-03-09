"""
E2E test for HTTP/2 client -> OpenProxy -> HTTP/1.1 upstream fallback framing.

This test is self-contained:
- starts a raw HTTP/1.1 upstream server that captures the exact request framing
- starts a dedicated OpenProxy instance with an HTTP/1.1-only upstream
- sends an HTTP/2 POST request through the proxy
- verifies the upstream request is re-framed as chunked and does not contain
  the client-supplied Content-Length header
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx


PROXY_AUTH_KEY = "h2-h1-fallback-auth-key"
UPSTREAM_API_KEY = "sk-upstream-fallback-key"
REQUEST_BODY = b"abcdefghij"


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


def wait_for_proxy_ready(port: int, cert_file: str, timeout: float = 20.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with httpx.Client(http2=True, verify=cert_file, timeout=2.0) as client:
                client.get(f"https://localhost:{port}/__ready__")
            return True
        except Exception:
            time.sleep(0.2)
    return False


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
            raise EOFError("unexpected EOF while reading upstream request")
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


def parse_request_head(head: bytes) -> tuple[str, dict[str, str]]:
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    request_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return request_line, headers


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


def start_capture_server(port: int, capture: dict) -> tuple[threading.Thread, threading.Event]:
    ready = threading.Event()

    def run():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(1)
        ready.set()

        conn, _ = server.accept()
        try:
            reader = BufferedSocketReader(conn)
            head = reader.read_until(b"\r\n\r\n")
            request_line, headers = parse_request_head(head)

            body = b""
            raw_body = b""
            if headers.get("transfer-encoding", "").lower() == "chunked":
                body, raw_body = read_chunked_body(reader)
            elif "content-length" in headers:
                body = reader.read_exact(int(headers["content-length"]))
                raw_body = body

            capture["request_line"] = request_line
            capture["headers"] = headers
            capture["body"] = body
            capture["raw_body"] = raw_body

            resp_body = json.dumps({"ok": True}).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                + b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(resp_body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + resp_body
            )
            conn.sendall(response)
        finally:
            conn.close()
            server.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, ready


def create_config(cert_file: str, key_file: str, proxy_port: int, upstream_port: int) -> str:
    authority = f"h1-fallback-framing.local:{proxy_port}"
    return f"""
cert_file: {cert_file}
private_key_file: {key_file}
https_port: {proxy_port}
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


def test_h2_h1_fallback_rebuilds_chunked_framing():
    print("\n" + "=" * 60)
    print("Testing H2->H1 fallback request framing")
    print("=" * 60)

    proxy_port = find_free_port()
    upstream_port = find_free_port()
    authority = f"h1-fallback-framing.local:{proxy_port}"
    capture: dict = {}

    capture_thread, ready = start_capture_server(upstream_port, capture)
    if not ready.wait(timeout=5):
        raise RuntimeError("capture server failed to start")

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file, key_file = generate_self_signed_cert(tmpdir)
        config_path = os.path.join(tmpdir, "config.yml")
        log_path = os.path.join(tmpdir, "openproxy.log")
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(create_config(cert_file, key_file, proxy_port, upstream_port))

        proxy_process, proxy_log = start_openproxy(config_path, log_path)
        failed = False
        try:
            if not wait_for_port("127.0.0.1", proxy_port, timeout=20):
                raise RuntimeError("openproxy TCP port did not open in time")
            if not wait_for_proxy_ready(proxy_port, cert_file, timeout=20):
                raise RuntimeError("openproxy HTTPS endpoint did not become ready in time")

            with httpx.Client(http2=True, verify=cert_file, timeout=10.0) as client:
                response = client.post(
                    f"https://localhost:{proxy_port}/capture",
                    headers={
                        "Host": authority,
                        "Authorization": f"Bearer {PROXY_AUTH_KEY}",
                        "Content-Length": str(len(REQUEST_BODY)),
                        "Content-Type": "application/octet-stream",
                    },
                    content=REQUEST_BODY,
                    extensions={"authority": authority},
                )

            print("Response status:", response.status_code)
            print("Response HTTP version:", response.http_version)
            print("x-upstream-protocol:", response.headers.get("x-upstream-protocol"))
            print("Captured upstream headers:", capture.get("headers"))

            assert response.status_code == 200, response.text
            assert response.http_version == "HTTP/2", response.http_version
            assert response.headers.get("x-upstream-protocol", "").lower() == "http/1.1"

            capture_thread.join(timeout=5)
            if capture_thread.is_alive():
                raise AssertionError("capture server thread did not finish")

            headers = capture.get("headers", {})
            assert capture.get("request_line") == "POST /capture HTTP/1.1"
            assert headers.get("host") == f"127.0.0.1:{upstream_port}"
            assert headers.get("connection", "").lower() == "keep-alive"
            assert headers.get("transfer-encoding", "").lower() == "chunked"
            assert "content-length" not in headers, headers
            assert headers.get("content-type") == "application/octet-stream"
            assert headers.get("authorization") == f"Bearer {UPSTREAM_API_KEY}"
            assert capture.get("body") == REQUEST_BODY
            assert capture.get("raw_body") == b"a\r\nabcdefghij\r\n0\r\n\r\n"

            print("✓ H2->H1 fallback framing test passed")
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
    test_h2_h1_fallback_rebuilds_chunked_framing()
