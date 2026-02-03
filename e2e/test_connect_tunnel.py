"""
E2E tests for HTTP CONNECT tunnel support.

These tests verify that:
1. CONNECT requests are handled correctly when enabled
2. CONNECT requests are rejected when disabled
3. Authentication works for CONNECT requests
4. The TCP tunnel correctly proxies data bidirectionally
"""

import os
import socket
import ssl
import threading
import time


def strip_url_scheme(host: str) -> str:
    """Strip https:// or http:// prefix and trailing slash from host."""
    if host.startswith("https://"):
        host = host[8:]
    elif host.startswith("http://"):
        host = host[7:]
    return host.rstrip("/")


def test_connect_tunnel_disabled():
    """Test that CONNECT requests return 403 when tunnel is disabled."""
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel when disabled")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT", "8080"))
    api_key = os.environ.get("OPENAI_API_KEY", "test-key")
    # Use TARGET_HOST to match CI provider config; strip URL scheme if present
    target_host = strip_url_scheme(os.environ.get("TARGET_HOST", "api.openai.com"))
    target_port = int(os.environ.get("TARGET_PORT", "443"))

    # Create a raw socket connection to send CONNECT request
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request
        request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode('utf-8', errors='replace')
        print(f"Response:\n{response_str}")

        # Should get 403 Forbidden when CONNECT is disabled
        assert "403" in response_str, f"Expected 403, got: {response_str}"
        assert "CONNECT" in response_str.lower() or "tunnel" in response_str.lower() or "not enabled" in response_str.lower(), \
            f"Expected message about CONNECT not enabled, got: {response_str}"

        print("\u2713 CONNECT tunnel disabled test passed!")

    finally:
        sock.close()


def test_connect_tunnel_enabled():
    """Test that CONNECT requests work correctly when enabled."""
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel when enabled")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT_CONNECT", "8081"))
    api_key = os.environ.get("OPENAI_API_KEY", "test-key")
    target_host = strip_url_scheme(os.environ.get("TARGET_HOST", "api.openai.com"))
    target_port = int(os.environ.get("TARGET_PORT", "443"))

    # Create a raw socket connection to send CONNECT request
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request
        request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode('utf-8', errors='replace')
        print(f"CONNECT Response:\n{response_str}")

        # Should get 200 Connection Established
        assert "200" in response_str, f"Expected 200, got: {response_str}"

        # Now the socket is a tunnel - upgrade to TLS
        context = ssl.create_default_context()
        ssl_sock = context.wrap_socket(sock, server_hostname=target_host)

        # Send a simple HTTP request through the tunnel
        http_request = (
            f"GET /v1/models HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        ssl_sock.sendall(http_request.encode())

        # Read response (might be 200 or 401 depending on API key validity)
        http_response = b""
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            http_response += chunk

        http_response_str = http_response.decode('utf-8', errors='replace')
        print(f"HTTP Response through tunnel (first 500 chars):\n{http_response_str[:500]}")

        # We should get a valid HTTP response (200 or 401)
        assert "HTTP/1.1" in http_response_str, f"Expected HTTP response, got: {http_response_str[:200]}"

        print("\u2713 CONNECT tunnel enabled test passed!")

    finally:
        try:
            sock.close()
        except Exception:
            pass


def test_connect_tunnel_upstream_tls_plaintext():
    """Test CONNECT tunnel with provider TLS enabled.

    In this mode, OpenProxy establishes a TLS connection to the upstream before
    returning "200 Connection Established". The client must NOT start a TLS
    handshake inside the tunnel. Instead, it should send plaintext application
    data (e.g., an HTTP/1.1 request) which OpenProxy will forward as TLS
    application data.

    This test validates the behavior by:
    1) CONNECTing to a provider host that is configured with tls: true
    2) Sending a plaintext HTTP request inside the tunnel
    3) Verifying we get an HTTP response back (200/401/etc)

    Required environment variables:
    - PROXY_HOST, PROXY_PORT_CONNECT
    - OPENAI_API_KEY (proxy auth key)
    - TARGET_HOST (real upstream hostname, used in Host header inside the tunnel)
    - TLS_CONNECT_HOST (provider host used for CONNECT, configured with tls: true)
    """
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel with upstream TLS (client sends plaintext)")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT_CONNECT", "8081"))
    api_key = os.environ.get("OPENAI_API_KEY", "test-key")

    connect_host = os.environ.get("TLS_CONNECT_HOST", "connect-tls")
    connect_port = int(os.environ.get("TLS_CONNECT_PORT", "443"))

    upstream_host = strip_url_scheme(os.environ.get("TARGET_HOST", "api.openai.com"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request to the tls:true provider host
        request = (
            f"CONNECT {connect_host}:{connect_port} HTTP/1.1\r\n"
            f"Host: {connect_host}:{connect_port}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        # Read CONNECT response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode("utf-8", errors="replace")
        print(f"CONNECT Response:\n{response_str}")

        # Should get 200 Connection Established
        assert "200" in response_str, f"Expected 200, got: {response_str}"

        # Send plaintext HTTP request through the tunnel
        http_request = (
            "GET /v1/models HTTP/1.1\r\n"
            f"Host: {upstream_host}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        sock.sendall(http_request.encode())

        # Read response (might be 200/401/etc depending on upstream auth)
        http_response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                http_response += chunk
                # Avoid unbounded reads; we only need the start of the response
                if len(http_response) > 64 * 1024:
                    break
        except socket.timeout:
            # If we already received some data, treat timeout as acceptable
            pass

        http_response_str = http_response.decode("utf-8", errors="replace")
        print(
            f"HTTP Response through tunnel (first 500 chars):\n{http_response_str[:500]}"
        )

        assert "HTTP/1.1" in http_response_str, (
            f"Expected HTTP response, got: {http_response_str[:200]}"
        )

        print("\u2713 CONNECT tunnel upstream TLS plaintext test passed!")

    finally:
        try:
            sock.close()
        except Exception:
            pass


def test_connect_tunnel_auth_failure():
    """Test that CONNECT requests with invalid auth return 401."""
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel authentication failure")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT_CONNECT", "8081"))
    # Use TARGET_HOST to match CI provider config
    target_host = strip_url_scheme(os.environ.get("TARGET_HOST", "api.openai.com"))
    target_port = int(os.environ.get("TARGET_PORT", "443"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request with invalid auth
        request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Authorization: Bearer invalid-key-12345\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode('utf-8', errors='replace')
        print(f"Response:\n{response_str}")

        # Should get 401 Unauthorized
        assert "401" in response_str, f"Expected 401, got: {response_str}"
        assert "authentication" in response_str.lower(), \
            f"Expected authentication error message, got: {response_str}"

        print("\u2713 CONNECT tunnel auth failure test passed!")

    finally:
        sock.close()


def test_connect_tunnel_no_provider():
    """Test that CONNECT requests for unknown hosts return 404."""
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel for unknown host")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT_CONNECT", "8081"))
    api_key = os.environ.get("OPENAI_API_KEY", "test-key")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request for unknown host
        request = (
            f"CONNECT unknown-host.example.com:443 HTTP/1.1\r\n"
            f"Host: unknown-host.example.com:443\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode('utf-8', errors='replace')
        print(f"Response:\n{response_str}")

        # Should get 404 Not Found
        assert "404" in response_str, f"Expected 404, got: {response_str}"
        assert "no provider" in response_str.lower(), \
            f"Expected 'no provider found' message, got: {response_str}"

        print("\u2713 CONNECT tunnel no provider test passed!")

    finally:
        sock.close()


def start_echo_server(host, port, ready_event):
    """Start a simple echo server for testing."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)
    server_sock.settimeout(5)
    ready_event.set()

    try:
        conn, addr = server_sock.accept()
        conn.settimeout(5)
        data = conn.recv(1024)
        if data:
            conn.sendall(data)  # Echo back
        conn.close()
    except socket.timeout:
        pass
    finally:
        server_sock.close()


def test_connect_tunnel_data_transfer():
    """Test that data is correctly transferred through the CONNECT tunnel.

    This test requires:
    - A provider configured for the echo target host (e.g., 'local-service')
    - The provider's port must match the echo server port
    - Environment variables: ECHO_TARGET_HOST, ECHO_TARGET_PORT
    """
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel data transfer")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT_CONNECT", "8081"))
    api_key = os.environ.get("OPENAI_API_KEY", "test-key")
    target_host = os.environ.get("ECHO_TARGET_HOST", "local-service")
    echo_port = int(os.environ.get("ECHO_TARGET_PORT", "19999"))

    # Start echo server
    echo_host = "127.0.0.1"
    ready_event = threading.Event()

    echo_thread = threading.Thread(
        target=start_echo_server,
        args=(echo_host, echo_port, ready_event)
    )
    echo_thread.daemon = True
    echo_thread.start()

    # Wait for server to be ready
    if not ready_event.wait(timeout=5):
        raise RuntimeError("Echo server failed to start within timeout")
    time.sleep(0.1)  # Give it a moment

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request
        request = (
            f"CONNECT {target_host}:{echo_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{echo_port}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        # Read CONNECT response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode('utf-8', errors='replace')
        print(f"CONNECT Response:\n{response_str}")

        # Must get 200 Connection Established
        assert "200" in response_str, f"Expected 200, got: {response_str}"

        # Send test data through tunnel
        test_data = b"Hello, CONNECT tunnel!"
        sock.sendall(test_data)

        # Receive echoed data - loop until we have all expected bytes (TCP may fragment)
        echoed = b""
        while len(echoed) < len(test_data):
            chunk = sock.recv(4096)
            if not chunk:
                break
            echoed += chunk

        print(f"Sent: {test_data}")
        print(f"Received: {echoed}")

        assert echoed == test_data, f"Data mismatch: sent {test_data}, received {echoed}"
        print("\u2713 CONNECT tunnel data transfer test passed!")

    finally:
        sock.close()
        echo_thread.join(timeout=1)


def test_connect_tunnel_preread():
    """Test that pre-read data (sent immediately after CONNECT headers) is forwarded correctly.

    This tests the critical fix for "optimistic CONNECT" where client sends data
    (e.g., TLS ClientHello) immediately after the CONNECT request headers, possibly
    in the same TCP segment. The proxy must forward this pre-read data to upstream
    after sending "200 Connection Established".

    This test requires:
    - A provider configured for the echo target host
    - The provider's port must match the echo server port
    - Environment variables: ECHO_TARGET_HOST, ECHO_TARGET_PORT
    """
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel pre-read data forwarding")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT_CONNECT", "8081"))
    api_key = os.environ.get("OPENAI_API_KEY", "test-key")
    target_host = os.environ.get("ECHO_TARGET_HOST", "local-service")
    echo_port = int(os.environ.get("ECHO_TARGET_PORT", "19999"))

    # Start echo server
    echo_host = "127.0.0.1"
    ready_event = threading.Event()

    echo_thread = threading.Thread(
        target=start_echo_server,
        args=(echo_host, echo_port, ready_event)
    )
    echo_thread.daemon = True
    echo_thread.start()

    # Wait for server to be ready
    if not ready_event.wait(timeout=5):
        raise RuntimeError("Echo server failed to start within timeout")
    time.sleep(0.1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request AND preread data in ONE sendall()
        # This simulates "optimistic CONNECT" behavior where client sends
        # data immediately after headers (e.g., TLS ClientHello)
        preread_payload = b"PREREAD_TEST_DATA_12345"
        request_with_preread = (
            f"CONNECT {target_host}:{echo_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{echo_port}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"\r\n"
        ).encode() + preread_payload

        print(f"Sending CONNECT + {len(preread_payload)} bytes preread in single sendall()")
        sock.sendall(request_with_preread)

        # Read CONNECT response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode('utf-8', errors='replace')
        print(f"CONNECT Response:\n{response_str}")

        # Must get 200 Connection Established
        assert "200" in response_str, f"Expected 200, got: {response_str}"

        # The echoed preread data might arrive with the 200 response (same TCP segment)
        # or in subsequent recv() calls. Collect until we have all expected bytes.
        header_end_idx = response.find(b"\r\n\r\n") + 4
        echoed = response[header_end_idx:]  # Start with any extra data after 200

        # Keep receiving until we have all the preread payload bytes
        while len(echoed) < len(preread_payload):
            chunk = sock.recv(4096)
            if not chunk:
                break
            echoed += chunk

        print(f"Preread sent: {preread_payload}")
        print(f"Echoed back: {echoed}")

        # The echo server should have received and echoed back the preread data
        assert echoed == preread_payload, \
            f"Preread data mismatch: sent {preread_payload}, received {echoed}"

        print("\u2713 CONNECT tunnel preread test passed!")

    finally:
        sock.close()
        echo_thread.join(timeout=1)


def test_connect_tunnel_port_mismatch():
    """Test that CONNECT requests with mismatched port return 400.

    When client requests CONNECT to host:port but the provider is configured
    for a different port, the proxy should return 400 Bad Request.
    """
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel port mismatch (400)")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT_CONNECT", "8081"))
    api_key = os.environ.get("OPENAI_API_KEY", "test-key")
    # Use TARGET_HOST but with a WRONG port
    target_host = strip_url_scheme(os.environ.get("TARGET_HOST", "api.openai.com"))
    target_port = int(os.environ.get("TARGET_PORT", "443"))
    # Pick a port that's definitely different from the configured one
    wrong_port = 8080 if target_port != 8080 else 8081

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request with wrong port
        request = (
            f"CONNECT {target_host}:{wrong_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{wrong_port}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode('utf-8', errors='replace')
        print(f"Response:\n{response_str}")

        # Should get 400 Bad Request with port mismatch message
        assert "400" in response_str, f"Expected 400, got: {response_str}"
        assert "does not match provider port" in response_str.lower(), \
            f"Expected 'does not match provider port' message, got: {response_str}"

        print("\u2713 CONNECT tunnel port mismatch test passed!")

    finally:
        sock.close()


def test_connect_tunnel_upstream_unreachable():
    """Test that CONNECT returns 502 when upstream is unreachable.

    When the provider's endpoint is unreachable (connection refused),
    the proxy should return 502 Bad Gateway.
    """
    print(f"\n{'='*50}")
    print("Testing CONNECT tunnel upstream unreachable (502)")
    print('='*50)

    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    proxy_port = int(os.environ.get("PROXY_PORT_CONNECT", "8081"))
    api_key = os.environ.get("OPENAI_API_KEY", "test-key")
    # Use the unreachable-service host configured for a closed port
    # Default port 19998 matches the CI provider config
    target_host = os.environ.get("UNREACHABLE_TARGET_HOST", "unreachable-service")
    unreachable_port = int(os.environ.get("UNREACHABLE_TARGET_PORT", "19998"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((proxy_host, proxy_port))

        # Send CONNECT request to unreachable endpoint
        request = (
            f"CONNECT {target_host}:{unreachable_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{unreachable_port}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_str = response.decode('utf-8', errors='replace')
        print(f"Response:\n{response_str}")

        # Should get 502 Bad Gateway
        assert "502" in response_str, f"Expected 502, got: {response_str}"
        assert "upstream" in response_str.lower() or "connection failed" in response_str.lower(), \
            f"Expected upstream connection failure message, got: {response_str}"

        print("\u2713 CONNECT tunnel upstream unreachable test passed!")

    finally:
        sock.close()


if __name__ == "__main__":
    import sys

    tests_run = 0

    # Run tests based on environment
    # Test disabled case (default config without connect_tunnel_enabled)
    if os.environ.get("TEST_CONNECT_DISABLED", "false").lower() == "true":
        test_connect_tunnel_disabled()
        tests_run += 1

    # Test enabled case with TLS handshake (requires real API endpoint)
    if os.environ.get("TEST_CONNECT_ENABLED", "false").lower() == "true":
        test_connect_tunnel_enabled()
        tests_run += 1

    # Test upstream TLS mode (provider tls: true, client sends plaintext inside tunnel)
    if os.environ.get("TEST_CONNECT_UPSTREAM_TLS", "false").lower() == "true":
        test_connect_tunnel_upstream_tls_plaintext()
        tests_run += 1

    # Test authentication failure (returns 401)
    if os.environ.get("TEST_CONNECT_AUTH_FAILURE", "false").lower() == "true":
        test_connect_tunnel_auth_failure()
        tests_run += 1

    # Test no provider found (returns 404)
    if os.environ.get("TEST_CONNECT_NO_PROVIDER", "false").lower() == "true":
        test_connect_tunnel_no_provider()
        tests_run += 1

    # Test data transfer (requires local echo server provider)
    if os.environ.get("TEST_CONNECT_DATA_TRANSFER", "false").lower() == "true":
        test_connect_tunnel_data_transfer()
        tests_run += 1

    # Test preread forwarding (requires local echo server provider)
    if os.environ.get("TEST_CONNECT_PREREAD", "false").lower() == "true":
        test_connect_tunnel_preread()
        tests_run += 1

    # Test port mismatch (returns 400)
    if os.environ.get("TEST_CONNECT_PORT_MISMATCH", "false").lower() == "true":
        test_connect_tunnel_port_mismatch()
        tests_run += 1

    # Test upstream unreachable (returns 502)
    if os.environ.get("TEST_CONNECT_UPSTREAM_UNREACHABLE", "false").lower() == "true":
        test_connect_tunnel_upstream_unreachable()
        tests_run += 1

    if tests_run == 0:
        print("\n" + "="*50)
        print("ERROR: No tests were run!")
        print("Set at least one of these environment variables to 'true':")
        print("  TEST_CONNECT_DISABLED")
        print("  TEST_CONNECT_ENABLED")
        print("  TEST_CONNECT_UPSTREAM_TLS")
        print("  TEST_CONNECT_AUTH_FAILURE")
        print("  TEST_CONNECT_NO_PROVIDER")
        print("  TEST_CONNECT_DATA_TRANSFER")
        print("  TEST_CONNECT_PREREAD")
        print("  TEST_CONNECT_PORT_MISMATCH")
        print("  TEST_CONNECT_UPSTREAM_UNREACHABLE")
        print("="*50)
        sys.exit(1)

    print("\n" + "="*50)
    print(f"\u2713 All {tests_run} CONNECT tunnel tests completed!")
    print("="*50)
