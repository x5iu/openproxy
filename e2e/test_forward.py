#!/usr/bin/env python3
"""E2E tests for forward provider - verifies transparent header forwarding."""

import os
import json
import httpx
import ssl


def test_forward_transparent_headers_https():
    """Test that forward provider passes all headers unchanged via HTTPS."""
    print("\n" + "=" * 50)
    print("Testing Forward Provider via HTTPS")
    print("=" * 50)

    proxy_https_port = os.environ.get("PROXY_HTTPS_PORT", "8443")
    ssl_cert_file = os.environ.get("SSL_CERT_FILE")

    base_url = f"https://localhost:{proxy_https_port}"

    ssl_context = ssl.create_default_context()
    if ssl_cert_file:
        ssl_context.load_verify_locations(ssl_cert_file)

    with httpx.Client(
        base_url=base_url, verify=ssl_context, http2=True, timeout=30
    ) as client:
        # Test 1: Headers are forwarded unchanged
        print("\nTest 1: Verify Authorization header is forwarded unchanged")
        test_auth_value = "Bearer client-test-token-12345"
        custom_header = "X-Custom-Header"
        custom_value = "custom-value-xyz"

        resp = client.get(
            "/test-forward",
            headers={
                "Host": f"forward.localhost:{proxy_https_port}",
                "Authorization": test_auth_value,
                custom_header: custom_value,
            },
        )

        print(f"  Status: {resp.status_code}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        print(f"  Response: {json.dumps(data, indent=2)}")

        # Verify the Authorization header was forwarded
        received_headers = data.get("headers", {})
        received_auth = received_headers.get("authorization")
        assert (
            received_auth == test_auth_value
        ), f"Authorization not forwarded correctly: expected '{test_auth_value}', got '{received_auth}'"
        print(f"  Authorization header forwarded: {received_auth}")

        # Verify custom header was forwarded
        # Header keys may be lowercase in the response
        received_custom = received_headers.get(custom_header.lower()) or received_headers.get(custom_header)
        assert (
            received_custom == custom_value
        ), f"Custom header not forwarded: expected '{custom_value}', got '{received_custom}'"
        print(f"  Custom header forwarded: {received_custom}")

        # Test 2: No extra auth headers added by proxy
        print("\nTest 2: Verify proxy doesn't add extra auth headers")

        # Check that there's no X-API-Key or other auth headers added by proxy
        x_api_key = received_headers.get("x-api-key")
        assert x_api_key is None, f"Proxy added unexpected X-API-Key header: {x_api_key}"
        print("  No unexpected X-API-Key header added by proxy")

        # Test 3: Request without Authorization header
        print("\nTest 3: Forward request without Authorization (should still work)")
        resp = client.get(
            "/test-no-auth",
            headers={
                "Host": f"forward.localhost:{proxy_https_port}",
            },
        )

        print(f"  Status: {resp.status_code}")
        assert (
            resp.status_code == 200
        ), f"Expected 200 for no-auth request, got {resp.status_code}"
        print("  Request without Authorization succeeded")

    print("\n" + "\u2713 Forward Provider HTTPS tests passed!")


def test_forward_transparent_headers_http():
    """Test that forward provider passes all headers unchanged via HTTP."""
    print("\n" + "=" * 50)
    print("Testing Forward Provider via HTTP")
    print("=" * 50)

    proxy_http_port = os.environ.get("PROXY_HTTP_PORT", "8080")
    base_url = f"http://localhost:{proxy_http_port}"

    with httpx.Client(base_url=base_url, http2=False, timeout=30) as client:
        # Test 1: Headers are forwarded unchanged
        print("\nTest 1: Verify Authorization header is forwarded unchanged")
        test_auth_value = "Bearer http-client-token-67890"
        custom_header = "X-Request-ID"
        custom_value = "req-12345"

        resp = client.get(
            "/test-http-forward",
            headers={
                "Host": f"forward.localhost:{proxy_http_port}",
                "Authorization": test_auth_value,
                custom_header: custom_value,
            },
        )

        print(f"  Status: {resp.status_code}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        print(f"  Response: {json.dumps(data, indent=2)}")

        received_headers = data.get("headers", {})
        received_auth = received_headers.get("authorization")
        assert (
            received_auth == test_auth_value
        ), f"Authorization not forwarded: expected '{test_auth_value}', got '{received_auth}'"
        print(f"  Authorization header forwarded: {received_auth}")

        # Test 2: POST request with body
        print("\nTest 2: Verify POST request body is forwarded")
        post_body = {"message": "test data", "count": 42}

        resp = client.post(
            "/test-post",
            headers={
                "Host": f"forward.localhost:{proxy_http_port}",
                "Authorization": "Bearer post-token",
                "Content-Type": "application/json",
            },
            json=post_body,
        )

        print(f"  Status: {resp.status_code}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        received_body = data.get("body")
        if isinstance(received_body, str):
            received_body = json.loads(received_body)
        assert (
            received_body == post_body
        ), f"Body not forwarded correctly: expected {post_body}, got {received_body}"
        print(f"  POST body forwarded correctly")

    print("\n" + "\u2713 Forward Provider HTTP tests passed!")


if __name__ == "__main__":
    test_forward_transparent_headers_https()
    test_forward_transparent_headers_http()

    print("\n" + "=" * 50)
    print("\u2713 All Forward Provider E2E tests passed!")
    print("=" * 50)
