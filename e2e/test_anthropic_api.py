"""
E2E tests for Anthropic API with multiple auth methods.

This test suite validates:
1. Anthropic Messages API with X-API-Key authentication
2. Anthropic Messages API with Authorization: Bearer authentication
3. OpenAI-compatible Chat Completions API
4. Both HTTP/1.1 and HTTP/2 protocols

Requires environment variables:
- PROXY_HTTPS_URL: The proxy HTTPS URL (e.g., https://localhost:8443)
- PROXY_HTTP_URL: The proxy HTTP URL (e.g., http://localhost:8080)
- ANTHROPIC_HOST: The host header for Anthropic provider (e.g., anthropic.localhost)
- OPENAI_API_KEY: The proxy auth key
- SSL_CERT_FILE: Path to SSL certificate for verification

Usage:
  python test_anthropic_api.py
"""

import os
import sys

import httpx


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

    proxy_http_url = get_env_or_fail("PROXY_HTTP_URL")
    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    auth_key = get_env_or_fail("OPENAI_API_KEY")

    with httpx.Client(
        base_url=proxy_http_url,
        http2=False,
        timeout=60,
    ) as client:
        print("Sending request with X-API-Key header...")
        response = client.post(
            "/v1/messages",
            headers={
                "Host": f"{anthropic_host}:8080",
                "Content-Type": "application/json",
                "X-API-Key": auth_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": "claude-3-haiku-20240307",
                "max_tokens": 50,
                "messages": [{"role": "user", "content": "Say 'Hello' in one word."}],
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

    assert data.get("id") is not None
    assert len(data.get("content", [])) > 0

    print("\u2713 Anthropic Messages API (HTTP/1.1 + X-API-Key) test passed!")


def test_anthropic_messages_bearer_http1():
    """
    Test Anthropic Messages API via HTTP/1.1 with Authorization: Bearer authentication.
    """
    print(f"\n{'='*60}")
    print("Testing Anthropic Messages API (HTTP/1.1 + Bearer)")
    print("=" * 60)

    proxy_http_url = get_env_or_fail("PROXY_HTTP_URL")
    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    auth_key = get_env_or_fail("OPENAI_API_KEY")

    with httpx.Client(
        base_url=proxy_http_url,
        http2=False,
        timeout=60,
    ) as client:
        print("Sending request with Authorization: Bearer header...")
        response = client.post(
            "/v1/messages",
            headers={
                "Host": f"{anthropic_host}:8080",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {auth_key}",
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": "claude-3-haiku-20240307",
                "max_tokens": 50,
                "messages": [{"role": "user", "content": "Say 'World' in one word."}],
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

    assert data.get("id") is not None
    assert len(data.get("content", [])) > 0

    print("\u2713 Anthropic Messages API (HTTP/1.1 + Bearer) test passed!")


def test_anthropic_messages_x_api_key_http2():
    """
    Test Anthropic Messages API via HTTP/2 with X-API-Key authentication.
    """
    print(f"\n{'='*60}")
    print("Testing Anthropic Messages API (HTTP/2 + X-API-Key)")
    print("=" * 60)

    proxy_https_url = get_env_or_fail("PROXY_HTTPS_URL")
    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    auth_key = get_env_or_fail("OPENAI_API_KEY")
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    with httpx.Client(
        base_url=proxy_https_url,
        http2=True,
        verify=ssl_cert if ssl_cert else True,
        timeout=60,
    ) as client:
        print("Sending request via HTTP/2 with X-API-Key...")
        response = client.post(
            "/v1/messages",
            headers={
                "Host": f"{anthropic_host}:8443",
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


def test_anthropic_messages_bearer_http2():
    """
    Test Anthropic Messages API via HTTP/2 with Authorization: Bearer authentication.
    """
    print(f"\n{'='*60}")
    print("Testing Anthropic Messages API (HTTP/2 + Bearer)")
    print("=" * 60)

    proxy_https_url = get_env_or_fail("PROXY_HTTPS_URL")
    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    auth_key = get_env_or_fail("OPENAI_API_KEY")
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    with httpx.Client(
        base_url=proxy_https_url,
        http2=True,
        verify=ssl_cert if ssl_cert else True,
        timeout=60,
    ) as client:
        print("Sending request via HTTP/2 with Authorization: Bearer...")
        response = client.post(
            "/v1/messages",
            headers={
                "Host": f"{anthropic_host}:8443",
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


def test_openai_compatible_http1():
    """
    Test Anthropic's OpenAI-compatible API via HTTP/1.1 with openai SDK.
    """
    print(f"\n{'='*60}")
    print("Testing OpenAI-compatible API (HTTP/1.1)")
    print("=" * 60)

    proxy_http_url = get_env_or_fail("PROXY_HTTP_URL")
    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    auth_key = get_env_or_fail("OPENAI_API_KEY")

    # Use openai SDK
    import openai

    client = openai.OpenAI(
        api_key=auth_key,
        base_url=f"{proxy_http_url}/v1",
        default_headers={"Host": f"{anthropic_host}:8080"},
        http_client=httpx.Client(http2=False),
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


def test_openai_compatible_http2():
    """
    Test Anthropic's OpenAI-compatible API via HTTP/2.
    """
    print(f"\n{'='*60}")
    print("Testing OpenAI-compatible API (HTTP/2)")
    print("=" * 60)

    proxy_https_url = get_env_or_fail("PROXY_HTTPS_URL")
    anthropic_host = get_env_or_fail("ANTHROPIC_HOST")
    auth_key = get_env_or_fail("OPENAI_API_KEY")
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    with httpx.Client(
        base_url=proxy_https_url,
        http2=True,
        verify=ssl_cert if ssl_cert else True,
        timeout=60,
    ) as client:
        print("Sending request via HTTP/2 to chat/completions...")
        response = client.post(
            "/v1/chat/completions",
            headers={
                "Host": f"{anthropic_host}:8443",
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
