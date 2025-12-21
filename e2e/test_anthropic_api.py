"""
E2E tests for Anthropic API with multiple auth methods.

This test suite validates:
1. Anthropic Messages API via anthropic SDK with X-API-Key
2. Anthropic Messages API via anthropic SDK with Authorization: Bearer
3. OpenAI-compatible Chat Completions API via openai SDK
4. Both HTTP/1.1 and HTTP/2 protocols

Requires environment variables:
- ANTHROPIC_HOST: The Anthropic API host (e.g., api.anthropic.com)
- ANTHROPIC_API_KEY: The Anthropic API key

Usage:
  python test_anthropic_api.py
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time

import httpx
import yaml


def find_free_port():
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        return s.getsockname()[1]


def wait_for_server(host, port, timeout=30):
    """Wait for the server to be ready."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (socket.error, ConnectionRefusedError):
            time.sleep(0.1)
    return False


def get_env_or_fail(name):
    """Get environment variable or fail with error."""
    value = os.environ.get(name)
    if not value:
        print(f"ERROR: {name} environment variable is not set")
        sys.exit(1)
    return value


def test_anthropic_messages_x_api_key_http1():
    """
    Test Anthropic Messages API via HTTP/1.1 with X-API-Key authentication.
    """
    print(f"\n{'='*60}")
    print("Testing Anthropic Messages API (HTTP/1.1 + X-API-Key)")
    print("=" * 60)

    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    anthropic_api_key = get_env_or_fail("ANTHROPIC_API_KEY")

    # Parse endpoint from host
    endpoint = anthropic_host.replace("https://", "").replace("http://", "").rstrip("/")

    # Find free port
    proxy_http_port = find_free_port()

    # Generate auth key
    auth_key = os.urandom(16).hex()

    # Create proxy config
    config = {
        "http_port": proxy_http_port,
        "auth_keys": [auth_key],
        "providers": [
            {
                "type": "anthropic",
                "host": "anthropic.local",
                "endpoint": endpoint,
                "api_key": anthropic_api_key,
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    print(f"Starting proxy on HTTP port {proxy_http_port}...")

    # Start the proxy
    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        if not wait_for_server("127.0.0.1", proxy_http_port, timeout=60):
            stdout, stderr = proxy_process.communicate(timeout=1)
            print(f"Proxy stdout: {stdout.decode()}")
            print(f"Proxy stderr: {stderr.decode()}")
            print("Failed to start proxy")
            sys.exit(1)

        print("Proxy ready")

        # Use anthropic SDK
        import anthropic

        client = anthropic.Anthropic(
            api_key=auth_key,  # Use proxy auth key
            base_url=f"http://127.0.0.1:{proxy_http_port}",
            default_headers={"Host": "anthropic.local"},
        )

        print("Sending request via anthropic SDK (X-API-Key)...")
        message = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=50,
            messages=[{"role": "user", "content": "Say 'Hello' in one word."}],
        )

        print(f"Response ID: {message.id}")
        print(f"Response content: {message.content[0].text[:100]}")
        print(f"Stop reason: {message.stop_reason}")
        print(f"Usage: input={message.usage.input_tokens}, output={message.usage.output_tokens}")

        assert message.id is not None
        assert len(message.content) > 0
        assert message.stop_reason == "end_turn"

        print("\u2713 Anthropic Messages API (HTTP/1.1 + X-API-Key) test passed!")

    finally:
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
        os.unlink(config_path)


def test_anthropic_messages_bearer_http1():
    """
    Test Anthropic Messages API via HTTP/1.1 with Authorization: Bearer authentication.
    """
    print(f"\n{'='*60}")
    print("Testing Anthropic Messages API (HTTP/1.1 + Bearer)")
    print("=" * 60)

    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    anthropic_api_key = get_env_or_fail("ANTHROPIC_API_KEY")

    endpoint = anthropic_host.replace("https://", "").replace("http://", "").rstrip("/")
    proxy_http_port = find_free_port()
    auth_key = os.urandom(16).hex()

    config = {
        "http_port": proxy_http_port,
        "auth_keys": [auth_key],
        "providers": [
            {
                "type": "anthropic",
                "host": "anthropic.local",
                "endpoint": endpoint,
                "api_key": anthropic_api_key,
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    print(f"Starting proxy on HTTP port {proxy_http_port}...")

    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        if not wait_for_server("127.0.0.1", proxy_http_port, timeout=60):
            print("Failed to start proxy")
            sys.exit(1)

        print("Proxy ready")

        # Use httpx with Authorization: Bearer header
        with httpx.Client(
            base_url=f"http://127.0.0.1:{proxy_http_port}",
            timeout=60,
        ) as client:
            print("Sending request with Authorization: Bearer header...")
            response = client.post(
                "/v1/messages",
                headers={
                    "Host": "anthropic.local",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {auth_key}",  # Use Bearer instead of X-API-Key
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 50,
                    "messages": [{"role": "user", "content": "Say 'World' in one word."}],
                },
            )

        print(f"Response status: {response.status_code}")

        if response.status_code != 200:
            print(f"Response body: {response.text}")
            sys.exit(1)

        data = response.json()
        print(f"Response ID: {data.get('id')}")
        print(f"Response content: {data.get('content', [{}])[0].get('text', '')[:100]}")

        assert data.get("id") is not None
        assert len(data.get("content", [])) > 0

        print("\u2713 Anthropic Messages API (HTTP/1.1 + Bearer) test passed!")

    finally:
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
        os.unlink(config_path)


def test_anthropic_messages_x_api_key_http2():
    """
    Test Anthropic Messages API via HTTP/2 with X-API-Key authentication.
    """
    print(f"\n{'='*60}")
    print("Testing Anthropic Messages API (HTTP/2 + X-API-Key)")
    print("=" * 60)

    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    anthropic_api_key = get_env_or_fail("ANTHROPIC_API_KEY")

    endpoint = anthropic_host.replace("https://", "").replace("http://", "").rstrip("/")
    proxy_https_port = find_free_port()
    auth_key = os.urandom(16).hex()

    # Generate self-signed certificate
    cert_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    key_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    cert_file.close()
    key_file.close()

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_file.name, "-out", cert_file.name,
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )

    config = {
        "https_port": proxy_https_port,
        "cert_file": cert_file.name,
        "private_key_file": key_file.name,
        "auth_keys": [auth_key],
        "providers": [
            {
                "type": "anthropic",
                "host": f"localhost:{proxy_https_port}",
                "endpoint": endpoint,
                "api_key": anthropic_api_key,
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    print(f"Starting proxy on HTTPS port {proxy_https_port}...")

    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        if not wait_for_server("127.0.0.1", proxy_https_port, timeout=60):
            print("Failed to start proxy")
            sys.exit(1)

        print("Proxy ready")

        # Use httpx with HTTP/2
        with httpx.Client(
            base_url=f"https://127.0.0.1:{proxy_https_port}",
            http2=True,
            verify=cert_file.name,
            timeout=60,
        ) as client:
            print("Sending request via HTTP/2 with X-API-Key...")
            response = client.post(
                "/v1/messages",
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": auth_key,
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 50,
                    "messages": [{"role": "user", "content": "Say 'HTTP2' in one word."}],
                },
            )

        print(f"Response status: {response.status_code}")
        print(f"HTTP version: {response.http_version}")

        if response.status_code != 200:
            print(f"Response body: {response.text}")
            sys.exit(1)

        data = response.json()
        print(f"Response ID: {data.get('id')}")
        print(f"Response content: {data.get('content', [{}])[0].get('text', '')[:100]}")

        assert response.http_version == "HTTP/2"
        assert data.get("id") is not None

        print("\u2713 Anthropic Messages API (HTTP/2 + X-API-Key) test passed!")

    finally:
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
        os.unlink(config_path)
        os.unlink(cert_file.name)
        os.unlink(key_file.name)


def test_anthropic_messages_bearer_http2():
    """
    Test Anthropic Messages API via HTTP/2 with Authorization: Bearer authentication.
    """
    print(f"\n{'='*60}")
    print("Testing Anthropic Messages API (HTTP/2 + Bearer)")
    print("=" * 60)

    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    anthropic_api_key = get_env_or_fail("ANTHROPIC_API_KEY")

    endpoint = anthropic_host.replace("https://", "").replace("http://", "").rstrip("/")
    proxy_https_port = find_free_port()
    auth_key = os.urandom(16).hex()

    # Generate self-signed certificate
    cert_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    key_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    cert_file.close()
    key_file.close()

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_file.name, "-out", cert_file.name,
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )

    config = {
        "https_port": proxy_https_port,
        "cert_file": cert_file.name,
        "private_key_file": key_file.name,
        "auth_keys": [auth_key],
        "providers": [
            {
                "type": "anthropic",
                "host": f"localhost:{proxy_https_port}",
                "endpoint": endpoint,
                "api_key": anthropic_api_key,
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    print(f"Starting proxy on HTTPS port {proxy_https_port}...")

    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        if not wait_for_server("127.0.0.1", proxy_https_port, timeout=60):
            print("Failed to start proxy")
            sys.exit(1)

        print("Proxy ready")

        # Use httpx with HTTP/2 and Bearer auth
        with httpx.Client(
            base_url=f"https://127.0.0.1:{proxy_https_port}",
            http2=True,
            verify=cert_file.name,
            timeout=60,
        ) as client:
            print("Sending request via HTTP/2 with Authorization: Bearer...")
            response = client.post(
                "/v1/messages",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {auth_key}",
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 50,
                    "messages": [{"role": "user", "content": "Say 'Bearer' in one word."}],
                },
            )

        print(f"Response status: {response.status_code}")
        print(f"HTTP version: {response.http_version}")

        if response.status_code != 200:
            print(f"Response body: {response.text}")
            sys.exit(1)

        data = response.json()
        print(f"Response ID: {data.get('id')}")
        print(f"Response content: {data.get('content', [{}])[0].get('text', '')[:100]}")

        assert response.http_version == "HTTP/2"
        assert data.get("id") is not None

        print("\u2713 Anthropic Messages API (HTTP/2 + Bearer) test passed!")

    finally:
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
        os.unlink(config_path)
        os.unlink(cert_file.name)
        os.unlink(key_file.name)


def test_openai_compatible_http1():
    """
    Test Anthropic's OpenAI-compatible API via HTTP/1.1 with openai SDK.
    """
    print(f"\n{'='*60}")
    print("Testing OpenAI-compatible API (HTTP/1.1)")
    print("=" * 60)

    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    anthropic_api_key = get_env_or_fail("ANTHROPIC_API_KEY")

    endpoint = anthropic_host.replace("https://", "").replace("http://", "").rstrip("/")
    proxy_http_port = find_free_port()
    auth_key = os.urandom(16).hex()

    config = {
        "http_port": proxy_http_port,
        "auth_keys": [auth_key],
        "providers": [
            {
                "type": "anthropic",
                "host": "anthropic.local",
                "endpoint": endpoint,
                "api_key": anthropic_api_key,
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    print(f"Starting proxy on HTTP port {proxy_http_port}...")

    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        if not wait_for_server("127.0.0.1", proxy_http_port, timeout=60):
            print("Failed to start proxy")
            sys.exit(1)

        print("Proxy ready")

        # Use openai SDK
        import openai

        client = openai.OpenAI(
            api_key=auth_key,
            base_url=f"http://127.0.0.1:{proxy_http_port}/v1",
            default_headers={"Host": "anthropic.local"},
        )

        print("Sending request via openai SDK (Chat Completions)...")
        response = client.chat.completions.create(
            model="claude-3-haiku-20240307",
            max_tokens=50,
            messages=[{"role": "user", "content": "Say 'OpenAI' in one word."}],
        )

        print(f"Response ID: {response.id}")
        print(f"Response content: {response.choices[0].message.content[:100]}")
        print(f"Finish reason: {response.choices[0].finish_reason}")

        assert response.id is not None
        assert len(response.choices) > 0

        print("\u2713 OpenAI-compatible API (HTTP/1.1) test passed!")

    finally:
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
        os.unlink(config_path)


def test_openai_compatible_http2():
    """
    Test Anthropic's OpenAI-compatible API via HTTP/2 with openai SDK.
    """
    print(f"\n{'='*60}")
    print("Testing OpenAI-compatible API (HTTP/2)")
    print("=" * 60)

    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    anthropic_api_key = get_env_or_fail("ANTHROPIC_API_KEY")

    endpoint = anthropic_host.replace("https://", "").replace("http://", "").rstrip("/")
    proxy_https_port = find_free_port()
    auth_key = os.urandom(16).hex()

    # Generate self-signed certificate
    cert_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    key_file = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)
    cert_file.close()
    key_file.close()

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_file.name, "-out", cert_file.name,
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )

    config = {
        "https_port": proxy_https_port,
        "cert_file": cert_file.name,
        "private_key_file": key_file.name,
        "auth_keys": [auth_key],
        "providers": [
            {
                "type": "anthropic",
                "host": f"localhost:{proxy_https_port}",
                "endpoint": endpoint,
                "api_key": anthropic_api_key,
            }
        ],
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False
    ) as config_file:
        yaml.dump(config, config_file)
        config_path = config_file.name

    print(f"Starting proxy on HTTPS port {proxy_https_port}...")

    proxy_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "start", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )

    try:
        if not wait_for_server("127.0.0.1", proxy_https_port, timeout=60):
            print("Failed to start proxy")
            sys.exit(1)

        print("Proxy ready")

        # Use httpx with HTTP/2 for OpenAI-compatible endpoint
        with httpx.Client(
            base_url=f"https://127.0.0.1:{proxy_https_port}",
            http2=True,
            verify=cert_file.name,
            timeout=60,
        ) as client:
            print("Sending request via HTTP/2 to chat/completions...")
            response = client.post(
                "/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {auth_key}",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 50,
                    "messages": [{"role": "user", "content": "Say 'Completions' in one word."}],
                },
            )

        print(f"Response status: {response.status_code}")
        print(f"HTTP version: {response.http_version}")

        if response.status_code != 200:
            print(f"Response body: {response.text}")
            sys.exit(1)

        data = response.json()
        print(f"Response ID: {data.get('id')}")
        print(f"Response content: {data.get('choices', [{}])[0].get('message', {}).get('content', '')[:100]}")

        assert response.http_version == "HTTP/2"
        assert data.get("id") is not None

        print("\u2713 OpenAI-compatible API (HTTP/2) test passed!")

    finally:
        proxy_process.terminate()
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_process.kill()
        os.unlink(config_path)
        os.unlink(cert_file.name)
        os.unlink(key_file.name)


if __name__ == "__main__":
    # Run all tests
    test_anthropic_messages_x_api_key_http1()
    test_anthropic_messages_bearer_http1()
    test_anthropic_messages_x_api_key_http2()
    test_anthropic_messages_bearer_http2()
    test_openai_compatible_http1()
    test_openai_compatible_http2()

    print("\n" + "=" * 60)
    print("\u2713 All Anthropic API E2E tests passed!")
    print("=" * 60)
