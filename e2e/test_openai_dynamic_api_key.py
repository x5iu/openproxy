"""
E2E tests for OpenAI dynamic API key support.

This test suite validates:
1. api_key: $(command) uses dynamic Authorization: Bearer header upstream
2. Standard (non-command) api_key behavior is unchanged
3. Health checks also use dynamic API key when configured
4. WebSocket upgrade also uses dynamic API key when configured
5. Dynamic api_key command failure returns 502 Bad Gateway
"""

import base64
import hashlib
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

WS_ACCEPT_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def find_free_port() -> int:
    """Find a free localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return sock.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Wait until a TCP port is accepting connections."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def find_openproxy_binary() -> str:
    """Find openproxy binary from env or local build outputs."""
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
    """Start openproxy and redirect logs to file."""
    binary = find_openproxy_binary()
    log_handle = open(log_path, "w")
    process = subprocess.Popen(
        [binary, "start", "-c", config_path],
        stdout=log_handle,
        stderr=log_handle,
    )
    return process, log_handle


def stop_process(process: subprocess.Popen):
    """Terminate a subprocess gracefully."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


class MockOpenAIHandler(BaseHTTPRequestHandler):
    """Mock upstream for OpenAI-style requests."""

    received_headers = {}
    authorization_values = []

    def log_message(self, format, *args):
        pass

    @classmethod
    def reset(cls):
        cls.received_headers = {}
        cls.authorization_values = []

    def do_GET(self):
        if self.path == "/health":
            MockOpenAIHandler.received_headers = {
                key.lower(): value for key, value in self.headers.items()
            }
            MockOpenAIHandler.authorization_values = (
                self.headers.get_all("Authorization") or []
            )

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        response = {"object": "list", "data": []}
        response_body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self):
        MockOpenAIHandler.received_headers = {
            key.lower(): value for key, value in self.headers.items()
        }
        MockOpenAIHandler.authorization_values = (
            self.headers.get_all("Authorization") or []
        )

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        response = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
        }
        response_body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)


def start_mock_server(port: int):
    """Start mock upstream server in background thread."""
    server = HTTPServer(("127.0.0.1", port), MockOpenAIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class MockWebSocketHandler(BaseHTTPRequestHandler):
    """Mock upstream for WebSocket upgrade requests."""

    received_headers = {}
    authorization_values = []

    def log_message(self, format, *args):
        pass

    @classmethod
    def reset(cls):
        cls.received_headers = {}
        cls.authorization_values = []

    def do_GET(self):
        MockWebSocketHandler.received_headers = {
            key.lower(): value for key, value in self.headers.items()
        }
        MockWebSocketHandler.authorization_values = (
            self.headers.get_all("Authorization") or []
        )

        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_response(400)
            self.end_headers()
            return

        sec_ws_key = self.headers.get("Sec-WebSocket-Key", "")
        sec_ws_accept = base64.b64encode(
            hashlib.sha1((sec_ws_key + WS_ACCEPT_MAGIC).encode("utf-8")).digest()
        ).decode("utf-8")

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", sec_ws_accept)
        self.end_headers()
        self.close_connection = True


def start_mock_websocket_server(port: int):
    """Start mock websocket upstream server in background thread."""
    server = HTTPServer(("127.0.0.1", port), MockWebSocketHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def read_http_response_header(sock: socket.socket, timeout: float = 10.0) -> str:
    """Read HTTP response headers from a socket."""
    sock.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("latin-1", errors="replace")


def test_dynamic_api_key_forwarding():
    """Dynamic api_key command should be executed and forwarded as Authorization."""
    import httpx
    import yaml

    print(f"\n{'=' * 60}")
    print("Testing OpenAI Dynamic API Key Forwarding")
    print("=" * 60)

    upstream_port = find_free_port()
    proxy_port = find_free_port()
    MockOpenAIHandler.reset()
    upstream_server = start_mock_server(upstream_port)

    if not wait_for_port("127.0.0.1", upstream_port):
        raise RuntimeError("Mock server failed to start")

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.yml")
        log_path = os.path.join(tmpdir, "openproxy.log")

        config = {
            "http_port": proxy_port,
            "providers": [
                {
                    "type": "openai",
                    "host": "openai-dynamic.local",
                    "endpoint": "127.0.0.1",
                    "port": upstream_port,
                    "tls": False,
                    "api_key": "$(echo sk-dynamic-openai-12345)",
                }
            ],
        }
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f)

        proxy_process, proxy_log = start_openproxy(config_path, log_path)
        try:
            if not wait_for_port("127.0.0.1", proxy_port, timeout=30):
                proxy_log.flush()
                with open(log_path, "r", encoding="utf-8") as f:
                    print(f.read())
                raise RuntimeError("openproxy failed to start")

            with httpx.Client(base_url=f"http://127.0.0.1:{proxy_port}", timeout=30, proxy=None) as client:
                response = client.post(
                    "/v1/chat/completions",
                    headers={
                        "Host": "openai-dynamic.local",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer client-should-not-pass-through",
                    },
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                )

            assert response.status_code == 200, f"Unexpected status: {response.status_code}"
            auth_values = MockOpenAIHandler.authorization_values
            assert len(auth_values) == 1, f"Expected 1 Authorization header, got: {auth_values}"
            assert auth_values[0] == "Bearer sk-dynamic-openai-12345", (
                f"Unexpected Authorization header: {auth_values[0]}"
            )
            print("Authorization at upstream:", auth_values[0])
            print("PASS: OpenAI dynamic API key forwarding test passed!")
        finally:
            stop_process(proxy_process)
            proxy_log.close()
            upstream_server.shutdown()
            upstream_server.server_close()


def test_standard_openai_api_key_still_works():
    """Static api_key behavior should remain unchanged."""
    import httpx
    import yaml

    print(f"\n{'=' * 60}")
    print("Testing OpenAI Standard API Key Mode")
    print("=" * 60)

    upstream_port = find_free_port()
    proxy_port = find_free_port()
    MockOpenAIHandler.reset()
    upstream_server = start_mock_server(upstream_port)

    if not wait_for_port("127.0.0.1", upstream_port):
        raise RuntimeError("Mock server failed to start")

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.yml")
        log_path = os.path.join(tmpdir, "openproxy.log")

        config = {
            "http_port": proxy_port,
            "providers": [
                {
                    "type": "openai",
                    "host": "openai-standard.local",
                    "endpoint": "127.0.0.1",
                    "port": upstream_port,
                    "tls": False,
                    "api_key": "sk-static-openai-67890",
                }
            ],
        }
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f)

        proxy_process, proxy_log = start_openproxy(config_path, log_path)
        try:
            if not wait_for_port("127.0.0.1", proxy_port, timeout=30):
                proxy_log.flush()
                with open(log_path, "r", encoding="utf-8") as f:
                    print(f.read())
                raise RuntimeError("openproxy failed to start")

            with httpx.Client(base_url=f"http://127.0.0.1:{proxy_port}", timeout=30, proxy=None) as client:
                response = client.post(
                    "/v1/chat/completions",
                    headers={
                        "Host": "openai-standard.local",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                )

            assert response.status_code == 200, f"Unexpected status: {response.status_code}"
            auth_values = MockOpenAIHandler.authorization_values
            assert len(auth_values) == 1, f"Expected 1 Authorization header, got: {auth_values}"
            assert auth_values[0] == "Bearer sk-static-openai-67890", (
                f"Unexpected Authorization header: {auth_values[0]}"
            )
            print("Authorization at upstream:", auth_values[0])
            print("PASS: OpenAI standard mode regression test passed!")
        finally:
            stop_process(proxy_process)
            proxy_log.close()
            upstream_server.shutdown()
            upstream_server.server_close()


def test_dynamic_api_key_health_check():
    """Health check should use dynamic Authorization header in command mode."""
    import yaml

    print(f"\n{'=' * 60}")
    print("Testing OpenAI Dynamic API Key Health Check")
    print("=" * 60)

    upstream_port = find_free_port()
    proxy_port = find_free_port()
    MockOpenAIHandler.reset()
    upstream_server = start_mock_server(upstream_port)

    if not wait_for_port("127.0.0.1", upstream_port):
        raise RuntimeError("Mock server failed to start")

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.yml")
        log_path = os.path.join(tmpdir, "openproxy.log")

        config = {
            "http_port": proxy_port,
            "health_check": {
                "enabled": True,
                "interval": 1,
            },
            "providers": [
                {
                    "type": "openai",
                    "host": "openai-health.local",
                    "endpoint": "127.0.0.1",
                    "port": upstream_port,
                    "tls": False,
                    "api_key": "$(echo sk-dynamic-health-abc)",
                    "health_check": {
                        "path": "/health",
                    },
                }
            ],
        }
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f)

        proxy_process, proxy_log = start_openproxy(config_path, log_path)
        try:
            if not wait_for_port("127.0.0.1", proxy_port, timeout=30):
                proxy_log.flush()
                with open(log_path, "r", encoding="utf-8") as f:
                    print(f.read())
                raise RuntimeError("openproxy failed to start")

            deadline = time.time() + 8.0
            while time.time() < deadline and not MockOpenAIHandler.authorization_values:
                time.sleep(0.2)

            auth_values = MockOpenAIHandler.authorization_values
            assert auth_values, "No health check request with Authorization header received"
            assert len(auth_values) == 1, f"Expected 1 Authorization header, got: {auth_values}"
            assert auth_values[0] == "Bearer sk-dynamic-health-abc", (
                f"Unexpected health check Authorization: {auth_values[0]}"
            )
            print("Health check Authorization at upstream:", auth_values[0])
            print("PASS: OpenAI dynamic API key health check test passed!")
        finally:
            stop_process(proxy_process)
            proxy_log.close()
            upstream_server.shutdown()
            upstream_server.server_close()


def test_dynamic_api_key_websocket_upgrade():
    """WebSocket upgrade should use dynamic Authorization header in command mode."""
    import yaml

    print(f"\n{'=' * 60}")
    print("Testing OpenAI Dynamic API Key WebSocket Upgrade")
    print("=" * 60)

    upstream_port = find_free_port()
    proxy_port = find_free_port()
    MockWebSocketHandler.reset()
    upstream_server = start_mock_websocket_server(upstream_port)

    if not wait_for_port("127.0.0.1", upstream_port):
        raise RuntimeError("Mock websocket server failed to start")

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.yml")
        log_path = os.path.join(tmpdir, "openproxy.log")

        config = {
            "http_port": proxy_port,
            "providers": [
                {
                    "type": "openai",
                    "host": "openai-ws-dynamic.local",
                    "endpoint": "127.0.0.1",
                    "port": upstream_port,
                    "tls": False,
                    "api_key": "$(echo sk-dynamic-ws-24680)",
                }
            ],
        }
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f)

        proxy_process, proxy_log = start_openproxy(config_path, log_path)
        try:
            if not wait_for_port("127.0.0.1", proxy_port, timeout=30):
                proxy_log.flush()
                with open(log_path, "r", encoding="utf-8") as f:
                    print(f.read())
                raise RuntimeError("openproxy failed to start")

            with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
                ws_request = (
                    "GET /v1/realtime?model=gpt-4o-mini HTTP/1.1\r\n"
                    "Host: openai-ws-dynamic.local\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    "Sec-WebSocket-Version: 13\r\n"
                    "Authorization: Bearer client-should-not-pass-through\r\n"
                    "\r\n"
                )
                sock.sendall(ws_request.encode("utf-8"))
                response_header = read_http_response_header(sock)

            status_line = response_header.split("\r\n", 1)[0]
            assert (
                "101" in status_line
            ), f"Expected WebSocket 101 response, got: {status_line}"

            auth_values = MockWebSocketHandler.authorization_values
            assert len(auth_values) == 1, f"Expected 1 Authorization header, got: {auth_values}"
            assert auth_values[0] == "Bearer sk-dynamic-ws-24680", (
                f"Unexpected WebSocket Authorization header: {auth_values[0]}"
            )
            print("WebSocket upstream Authorization:", auth_values[0])
            print("PASS: OpenAI dynamic API key websocket test passed!")
        finally:
            stop_process(proxy_process)
            proxy_log.close()
            upstream_server.shutdown()
            upstream_server.server_close()


def test_dynamic_api_key_command_failure_returns_502():
    """Dynamic command failure should return 502 without contacting upstream."""
    import httpx
    import yaml

    print(f"\n{'=' * 60}")
    print("Testing OpenAI Dynamic API Key Command Failure")
    print("=" * 60)

    proxy_port = find_free_port()

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.yml")
        log_path = os.path.join(tmpdir, "openproxy.log")

        config = {
            "http_port": proxy_port,
            "providers": [
                {
                    "type": "openai",
                    "host": "openai-command-fail.local",
                    "endpoint": "127.0.0.1",
                    "port": find_free_port(),
                    "tls": False,
                    "api_key": "$(exit 1)",
                }
            ],
        }
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f)

        proxy_process, proxy_log = start_openproxy(config_path, log_path)
        try:
            if not wait_for_port("127.0.0.1", proxy_port, timeout=30):
                proxy_log.flush()
                with open(log_path, "r", encoding="utf-8") as f:
                    print(f.read())
                raise RuntimeError("openproxy failed to start")

            with httpx.Client(base_url=f"http://127.0.0.1:{proxy_port}", timeout=30, proxy=None) as client:
                response = client.post(
                    "/v1/chat/completions",
                    headers={
                        "Host": "openai-command-fail.local",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer client-auth",
                    },
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                )

            assert response.status_code == 502, f"Expected 502, got: {response.status_code}"
            assert "upstream authentication failed" in response.text, (
                f"Unexpected response body: {response.text}"
            )
            print("Response body:", response.text)
            print("PASS: OpenAI dynamic command failure returns 502 test passed!")
        finally:
            stop_process(proxy_process)
            proxy_log.close()


if __name__ == "__main__":
    try:
        test_dynamic_api_key_forwarding()
        test_standard_openai_api_key_still_works()
        test_dynamic_api_key_health_check()
        test_dynamic_api_key_websocket_upgrade()
        test_dynamic_api_key_command_failure_returns_502()
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("PASS: All OpenAI dynamic API key tests passed!")
    print("=" * 60)
