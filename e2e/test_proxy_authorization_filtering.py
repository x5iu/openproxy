"""
E2E tests for Proxy-Authorization filtering.

These tests verify that Proxy-Authorization is never forwarded upstream:
1. HTTP/2 ingress with HTTP/1.1 fallback upstream
2. HTTP/1.1 WebSocket upgrade
"""

import base64
import hashlib
import httpx
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


PROXY_HTTPS_PORT = 28444
PROXY_HTTP_PORT = 28082
HTTP_ECHO_PORT = 29010
WS_CAPTURE_PORT = 29011

AUTH_KEY = "proxy-auth-key"
PROVIDER_API_KEY = "sk-provider-auth-key"
PROXY_AUTH_VALUE = "Bearer should-not-leak"

HTTP2_HOST = f"proxy-filter-h2.local:{PROXY_HTTPS_PORT}"
WS_HOST = f"proxy-filter-ws.local:{PROXY_HTTP_PORT}"
WS_ACCEPT_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class EchoHeadersHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self):
        headers_multi = {}
        for key, value in self.headers.items():
            lower = key.lower()
            headers_multi.setdefault(lower, []).append(value)

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

    def do_GET(self):
        self._send()

    def log_message(self, *args):
        pass


class WebSocketCaptureServer:
    def __init__(self, port: int):
        self.port = port
        self.request_text = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()
        wait_for_port(self.port)

    def stop(self) -> None:
        self._stop.set()
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                pass
        except OSError:
            pass
        self._thread.join(timeout=5)

    def wait_for_request(self, timeout: float = 5.0) -> str:
        if not self._ready.wait(timeout):
            raise TimeoutError("Timed out waiting for WebSocket capture request")
        assert self.request_text is not None
        return self.request_text

    def _serve(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", self.port))
            server.listen(5)
            server.settimeout(1)

            while not self._stop.is_set():
                try:
                    conn, _addr = server.accept()
                except socket.timeout:
                    continue

                with conn:
                    data = b""
                    conn.settimeout(2)
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk

                    if not data:
                        continue

                    self.request_text = data.decode("utf-8", errors="replace")
                    self._ready.set()

                    sec_ws_key = None
                    for line in self.request_text.split("\r\n"):
                        if line.lower().startswith("sec-websocket-key:"):
                            sec_ws_key = line.split(":", 1)[1].strip()
                            break

                    if not sec_ws_key:
                        return

                    accept = base64.b64encode(
                        hashlib.sha1((sec_ws_key + WS_ACCEPT_MAGIC).encode("utf-8")).digest()
                    ).decode("utf-8")

                    response = (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n"
                        "\r\n"
                    )
                    conn.sendall(response.encode("utf-8"))
                    time.sleep(0.2)
                    return


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


def generate_sec_websocket_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


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
    host: {HTTP2_HOST}
    endpoint: localhost
    port: {HTTP_ECHO_PORT}
    tls: false
    api_key: {PROVIDER_API_KEY}
  - type: openai
    host: {WS_HOST}
    endpoint: localhost
    port: {WS_CAPTURE_PORT}
    tls: false
    api_key: {PROVIDER_API_KEY}
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


def test_h2_fallback_filters_proxy_authorization(cert_file: str) -> None:
    print("\nTesting HTTP/2 ingress -> HTTP/1.1 upstream fallback filtering")
    with httpx.Client(verify=cert_file, http2=True, timeout=30) as client:
        response = client.get(
            f"https://localhost:{PROXY_HTTPS_PORT}/v1/test",
            headers={
                "Host": HTTP2_HOST,
                "Authorization": f"Bearer {AUTH_KEY}",
                "Proxy-Authorization": PROXY_AUTH_VALUE,
            },
        )

    print(f"  Status: {response.status_code}")
    print(f"  HTTP version: {response.http_version}")
    assert response.status_code == 200

    data = response.json()
    headers = data["headers"]
    print(json.dumps(data, indent=2))

    assert response.http_version == "HTTP/2"
    assert headers.get("proxy-authorization") is None, headers
    assert headers.get("authorization") == [f"Bearer {PROVIDER_API_KEY}"], headers


def test_websocket_filters_proxy_authorization() -> None:
    print("\nTesting WebSocket upgrade filtering")
    sec_websocket_key = generate_sec_websocket_key()
    request = (
        f"GET /v1/realtime HTTP/1.1\r\n"
        f"Host: {WS_HOST}\r\n"
        f"Authorization: Bearer {AUTH_KEY}\r\n"
        f"Proxy-Authorization: {PROXY_AUTH_VALUE}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {sec_websocket_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("utf-8")

    with socket.create_connection(("127.0.0.1", PROXY_HTTP_PORT), timeout=10) as sock:
        sock.settimeout(5)
        sock.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

    response_text = response.decode("utf-8", errors="replace")
    print(response_text)
    assert "101 Switching Protocols" in response_text, response_text


def main() -> None:
    http_server, _http_thread = start_http_echo_server()
    ws_server = WebSocketCaptureServer(WS_CAPTURE_PORT)
    ws_server.start()

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file, key_file = generate_self_signed_cert(tmpdir)
        config_file = os.path.join(tmpdir, "config.yml")
        log_file = os.path.join(tmpdir, "openproxy.log")
        create_config(config_file, cert_file, key_file)
        proxy, log_handle = start_openproxy(config_file, log_file)

        try:
            test_h2_fallback_filters_proxy_authorization(cert_file)
            test_websocket_filters_proxy_authorization()

            captured = ws_server.wait_for_request()
            print(captured)
            assert "Proxy-Authorization:" not in captured
            assert f"Authorization: Bearer {PROVIDER_API_KEY}\r\n" in captured

            print("\nAll Proxy-Authorization filtering E2E tests passed.")
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
            ws_server.stop()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Test failed: {exc}", file=sys.stderr)
        raise
