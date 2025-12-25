#!/usr/bin/env python3
"""
E2E tests for auth-during-provider-selection feature.

This tests the scenario where multiple providers match the same host/path,
but have different auth_keys. The proxy should authenticate against all
matching providers and select one that passes authentication.

This test uses the proxy already started by the e2e workflow.
"""

import os
import httpx


# Configuration from environment
HTTPS_PORT = int(os.environ.get("PROXY_HTTPS_PORT", "8443"))
HTTP_PORT = int(os.environ.get("PROXY_HTTP_PORT", "8080"))
SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE", "")


def test_auth_selects_correct_provider():
    """Test that authentication during provider selection works correctly."""
    print("\n=== Testing auth-during-provider-selection ===\n")

    # Test 1: HTTPS request with key valid for provider1
    print("Test 1: HTTPS request with key valid for provider1...")
    with httpx.Client(verify=SSL_CERT_FILE) as client:
        resp = client.get(
            f"https://localhost:{HTTPS_PORT}/v1/test",
            headers={
                "Host": f"auth-test.local:{HTTPS_PORT}",
                "Authorization": "Bearer sk-auth-key-1",
            },
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        assert data["server_id"] == "provider1", f"Expected provider1, got {data['server_id']}"
        print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 2: HTTPS request with key valid for provider2
    print("Test 2: HTTPS request with key valid for provider2...")
    with httpx.Client(verify=SSL_CERT_FILE) as client:
        resp = client.get(
            f"https://localhost:{HTTPS_PORT}/v1/test",
            headers={
                "Host": f"auth-test.local:{HTTPS_PORT}",
                "Authorization": "Bearer sk-auth-key-2",
            },
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        assert data["server_id"] == "provider2", f"Expected provider2, got {data['server_id']}"
        print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 3: HTTPS request with key valid only for fallback
    # Non-fallback providers should fail auth, then fallback should be selected
    print("Test 3: HTTPS request with key valid only for fallback...")
    with httpx.Client(verify=SSL_CERT_FILE) as client:
        resp = client.get(
            f"https://localhost:{HTTPS_PORT}/v1/test",
            headers={
                "Host": f"auth-test.local:{HTTPS_PORT}",
                "Authorization": "Bearer sk-auth-key-fallback",
            },
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        assert data["server_id"] == "fallback", f"Expected fallback, got {data['server_id']}"
        print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 4: HTTPS request with invalid key (should fail with 401)
    print("Test 4: HTTPS request with invalid key (should return 401)...")
    with httpx.Client(verify=SSL_CERT_FILE) as client:
        resp = client.get(
            f"https://localhost:{HTTPS_PORT}/v1/test",
            headers={
                "Host": f"auth-test.local:{HTTPS_PORT}",
                "Authorization": "Bearer invalid-key",
            },
        )
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
        print(f"  -> Got 401 as expected ✓")

    # Test 5: HTTP/1.1 request with key for provider1
    print("Test 5: HTTP request with key for provider1...")
    with httpx.Client() as client:
        resp = client.get(
            f"http://localhost:{HTTP_PORT}/v1/test",
            headers={
                "Host": f"auth-test.local:{HTTP_PORT}",
                "Authorization": "Bearer sk-auth-key-1",
            },
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        assert data["server_id"] == "provider1", f"Expected provider1, got {data['server_id']}"
        print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 6: HTTP/1.1 request with fallback key
    print("Test 6: HTTP request with key for fallback...")
    with httpx.Client() as client:
        resp = client.get(
            f"http://localhost:{HTTP_PORT}/v1/test",
            headers={
                "Host": f"auth-test.local:{HTTP_PORT}",
                "Authorization": "Bearer sk-auth-key-fallback",
            },
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        assert data["server_id"] == "fallback", f"Expected fallback, got {data['server_id']}"
        print(f"  -> Routed to: {data['server_id']} ✓")

    # Test 7: HTTP/1.1 request with invalid key (should fail with 401)
    print("Test 7: HTTP request with invalid key (should return 401)...")
    with httpx.Client() as client:
        resp = client.get(
            f"http://localhost:{HTTP_PORT}/v1/test",
            headers={
                "Host": f"auth-test.local:{HTTP_PORT}",
                "Authorization": "Bearer invalid-key",
            },
        )
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
        print(f"  -> Got 401 as expected ✓")

    print("\n=== All tests passed! ===\n")


if __name__ == "__main__":
    test_auth_selects_correct_provider()
