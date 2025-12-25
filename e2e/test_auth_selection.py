#!/usr/bin/env python3
"""
E2E tests for auth-during-provider-selection feature.

This tests the scenario where multiple providers match the same host/path,
but have different auth_keys. The proxy should authenticate against all
matching providers and select one that passes authentication.

This test uses the proxy already started by the e2e workflow.
"""

import os
import json
import ssl
import urllib.request
import urllib.error


# Configuration from environment
HTTPS_PORT = int(os.environ.get("PROXY_HTTPS_PORT", "8443"))
HTTP_PORT = int(os.environ.get("PROXY_HTTP_PORT", "8080"))
SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE", "")


def http_request(url: str, headers: dict, ssl_context=None) -> tuple:
    """Make an HTTP request and return (status_code, response_body)."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_auth_selects_correct_provider():
    """Test that authentication during provider selection works correctly."""
    print("\n=== Testing auth-during-provider-selection ===\n")

    # Create SSL context that trusts the self-signed cert
    ssl_context = None
    if SSL_CERT_FILE:
        ssl_context = ssl.create_default_context()
        ssl_context.load_verify_locations(SSL_CERT_FILE)

    # Test 1: HTTPS request with key valid for provider1
    print("Test 1: HTTPS request with key valid for provider1...")
    status, data = http_request(
        f"https://localhost:{HTTPS_PORT}/v1/test",
        headers={
            "Host": f"auth-test.local:{HTTPS_PORT}",
            "Authorization": "Bearer sk-auth-provider1",
        },
        ssl_context=ssl_context,
    )
    assert status == 200, f"Expected 200, got {status}"
    assert data["server_id"] == "provider1", f"Expected provider1, got {data['server_id']}"
    print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 2: HTTPS request with key valid for provider2
    print("Test 2: HTTPS request with key valid for provider2...")
    status, data = http_request(
        f"https://localhost:{HTTPS_PORT}/v1/test",
        headers={
            "Host": f"auth-test.local:{HTTPS_PORT}",
            "Authorization": "Bearer sk-auth-provider2",
        },
        ssl_context=ssl_context,
    )
    assert status == 200, f"Expected 200, got {status}"
    assert data["server_id"] == "provider2", f"Expected provider2, got {data['server_id']}"
    print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 3: HTTPS request with key valid only for fallback
    # Non-fallback providers should fail auth, then fallback should be selected
    print("Test 3: HTTPS request with key valid only for fallback...")
    status, data = http_request(
        f"https://localhost:{HTTPS_PORT}/v1/test",
        headers={
            "Host": f"auth-test.local:{HTTPS_PORT}",
            "Authorization": "Bearer sk-auth-fallback",
        },
        ssl_context=ssl_context,
    )
    assert status == 200, f"Expected 200, got {status}"
    assert data["server_id"] == "fallback", f"Expected fallback, got {data['server_id']}"
    print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 4: HTTPS request with invalid key (should fail with 401)
    print("Test 4: HTTPS request with invalid key (should return 401)...")
    status, data = http_request(
        f"https://localhost:{HTTPS_PORT}/v1/test",
        headers={
            "Host": f"auth-test.local:{HTTPS_PORT}",
            "Authorization": "Bearer invalid-key",
        },
        ssl_context=ssl_context,
    )
    assert status == 401, f"Expected 401, got {status}"
    print(f"  -> Got 401 as expected ✓")

    # Test 5: HTTP/1.1 request with key for provider1
    print("Test 5: HTTP request with key for provider1...")
    status, data = http_request(
        f"http://localhost:{HTTP_PORT}/v1/test",
        headers={
            "Host": f"auth-test.local:{HTTP_PORT}",
            "Authorization": "Bearer sk-auth-provider1",
        },
    )
    assert status == 200, f"Expected 200, got {status}"
    assert data["server_id"] == "provider1", f"Expected provider1, got {data['server_id']}"
    print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 6: HTTP/1.1 request with fallback key
    print("Test 6: HTTP request with key for fallback...")
    status, data = http_request(
        f"http://localhost:{HTTP_PORT}/v1/test",
        headers={
            "Host": f"auth-test.local:{HTTP_PORT}",
            "Authorization": "Bearer sk-auth-fallback",
        },
    )
    assert status == 200, f"Expected 200, got {status}"
    assert data["server_id"] == "fallback", f"Expected fallback, got {data['server_id']}"
    print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 7: HTTP/1.1 request with invalid key (should fail with 401)
    print("Test 7: HTTP request with invalid key (should return 401)...")
    status, data = http_request(
        f"http://localhost:{HTTP_PORT}/v1/test",
        headers={
            "Host": f"auth-test.local:{HTTP_PORT}",
            "Authorization": "Bearer invalid-key",
        },
    )
    assert status == 401, f"Expected 401, got {status}"
    print(f"  -> Got 401 as expected ✓")

    print("\n=== All tests passed! ===\n")


if __name__ == "__main__":
    test_auth_selects_correct_provider()
