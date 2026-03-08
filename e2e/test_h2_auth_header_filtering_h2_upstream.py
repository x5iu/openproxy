"""
E2E test for HTTP/2 auth header filtering on the HTTP/2 upstream path.

This verifies that when the upstream supports HTTP/2, the proxy still strips
all client auth headers from all matching providers and only forwards the
selected provider's auth header.

Uses a local HTTP/2 echo server (via the h2 library) instead of external services.
"""

import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import h2.config
import h2.connection
import h2.events
import httpx


PROXY_HTTPS_PORT = 28447
PROXY_HTTP_PORT = 28085
UPSTREAM_PORT = 29014

AUTH_KEY = "shared-auth-key"
OPENAI_PROVIDER_API_KEY = "sk-openai-h2-upstream-key"
CLIENT_X_API_KEY = AUTH_KEY
TEST_HOST = f"shared-auth-h2.local:{PROXY_HTTPS_PORT}"


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


def handle_h2_connection(conn: ssl.SSLSocket) -> None:
    """Handle a single HTTP/2 connection, echo back headers as JSON."""
    config = h2.config.H2Configuration(client_side=False)
    h2_conn = h2.connection.H2Connection(config=config)
    h2_conn.initiate_connection()
    conn.sendall(h2_conn.data_to_send())

    # Accumulate request headers per stream
    stream_headers: dict[int, list[tuple[str, str]]] = {}
    stream_data: dict[int, bytes] = {}

    while True:
        try:
            data = conn.recv(65535)
        except (ConnectionError, OSError):
            break
        if not data:
            break

        events = h2_conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                stream_headers[event.stream_id] = event.headers

            elif isinstance(event, h2.events.DataReceived):
                stream_data.setdefault(event.stream_id, b"")
                stream_data[event.stream_id] += event.data
                h2_conn.increment_flow_control_window(
                    event.flow_controlled_length, event.stream_id
                )

            elif isinstance(event, h2.events.StreamEnded):
                sid = event.stream_id
                headers_list = stream_headers.pop(sid, [])
                headers_dict: dict[str, list[str]] = {}
                path = "/"
                for name, value in headers_list:
                    n = name if isinstance(name, str) else name.decode()
                    v = value if isinstance(value, str) else value.decode()
                    if n == ":path":
                        path = v
                        continue
                    if n.startswith(":"):
                        continue
                    headers_dict.setdefault(n, []).append(v)

                body = json.dumps(
                    {"headers": headers_dict, "path": path}
                ).encode("utf-8")

                response_headers = [
                    (":status", "200"),
                    ("content-type", "application/json"),
                    ("content-length", str(len(body))),
                ]
                h2_conn.send_headers(sid, response_headers)
                h2_conn.send_data(sid, body, end_stream=True)

            elif isinstance(event, h2.events.WindowUpdated):
                pass

        out = h2_conn.data_to_send()
        if out:
            conn.sendall(out)


def start_h2_echo_server(
    cert_file: str, key_file: str
) -> tuple[socket.socket, threading.Thread]:
    """Start a local TLS HTTP/2 echo server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    ctx.set_alpn_protocols(["h2"])

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", UPSTREAM_PORT))
    server_sock.listen(5)
    server_sock.settimeout(1.0)

    def serve() -> None:
        while not getattr(serve, "stop", False):
            try:
                client_sock, _ = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls_conn = ctx.wrap_socket(client_sock, server_side=True)
                handle_h2_connection(tls_conn)
                tls_conn.close()
            except Exception:
                try:
                    client_sock.close()
                except Exception:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    wait_for_port(UPSTREAM_PORT)
    return server_sock, thread


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
    port: {UPSTREAM_PORT}
    tls: true
    api_key: {OPENAI_PROVIDER_API_KEY}
    priority: 10
  - type: anthropic
    host: {TEST_HOST}
    endpoint: localhost
    port: {UPSTREAM_PORT}
    tls: true
    api_key: anthropic-upstream-key
    priority: 0
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
    wait_for_port(PROXY_HTTPS_PORT)
    return process, log_handle


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file, key_file = generate_self_signed_cert(tmpdir)

        # Start local HTTP/2 echo server (upstream)
        server_sock, server_thread = start_h2_echo_server(cert_file, key_file)

        config_file = os.path.join(tmpdir, "config.yml")
        log_file = os.path.join(tmpdir, "openproxy.log")
        create_config(config_file, cert_file, key_file)
        proxy, log_handle = start_openproxy(config_file, log_file)

        try:
            print("\nTesting HTTP/2 auth header filtering on HTTP/2 upstream")
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

            # OpenAI provider should inject its own auth header
            assert headers.get("authorization") == [
                f"Bearer {OPENAI_PROVIDER_API_KEY}"
            ], headers
            # Anthropic's x-api-key must be stripped
            assert "x-api-key" not in headers, headers
            # No proxy-authorization should leak
            assert "proxy-authorization" not in headers, headers

            print("\nHTTP/2 -> HTTP/2 auth header filtering E2E test passed.")
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=5)
            log_handle.close()
            server_thread.stop = True  # type: ignore[attr-defined]
            server_sock.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Test failed: {exc}", file=sys.stderr)
        raise
