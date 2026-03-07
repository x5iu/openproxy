"""
E2E tests for provider priority selection.

This test reuses the auth-selection providers configured by the workflow:
- provider1: non-fallback, priority 10
- provider2: non-fallback, priority 1
- fallback: fallback, priority 100

The request uses the global AUTH_KEY so all three providers can authenticate.
Expected behavior:
- provider1 wins because it is the highest-priority non-fallback provider
- fallback must not override non-fallback selection even with a higher priority
"""

import os
import httpx


HTTPS_PORT = int(os.environ.get("PROXY_HTTPS_PORT", "8443"))
HTTP_PORT = int(os.environ.get("PROXY_HTTP_PORT", "8080"))
SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE", "")
AUTH_KEY = os.environ["AUTH_KEY"]


def test_provider_priority_https():
    """Highest-priority non-fallback provider should win over lower priority and fallback."""
    print("\n=== Testing provider priority over HTTPS ===\n")

    with httpx.Client(verify=SSL_CERT_FILE) as client:
        resp = client.get(
            f"https://localhost:{HTTPS_PORT}/v1/priority",
            headers={
                "Host": f"auth-test.local:{HTTPS_PORT}",
                "Authorization": f"Bearer {AUTH_KEY}",
            },
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        assert data["server_id"] == "provider1", f"Expected provider1, got {data['server_id']}"
        print(f"  -> Routed to: {data['server_id']} ✓")


def test_provider_priority_http():
    """Highest-priority non-fallback provider should also win on HTTP/1.1."""
    print("\n=== Testing provider priority over HTTP ===\n")

    with httpx.Client() as client:
        resp = client.get(
            f"http://localhost:{HTTP_PORT}/v1/priority",
            headers={
                "Host": f"auth-test.local:{HTTP_PORT}",
                "Authorization": f"Bearer {AUTH_KEY}",
            },
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        assert data["server_id"] == "provider1", f"Expected provider1, got {data['server_id']}"
        print(f"  -> Routed to: {data['server_id']} ✓")


if __name__ == "__main__":
    test_provider_priority_https()
    test_provider_priority_http()
    print("\n=== Provider priority E2E tests passed! ===\n")
