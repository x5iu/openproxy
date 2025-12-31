"""E2E regression test for large HTTP/2 request bodies.

This reproduces a hang where:
- client -> openproxy uses HTTP/2
- openproxy -> upstream uses HTTP/2
- request body is large (> 100KB)

Symptom: client never receives response headers (hang / timeout).
"""

import json
import os
import time

import httpx


def test_h2_large_body_request():
    print(f"\n{'='*50}")
    print("Testing HTTP/2 large request body (>=100KB)")
    print("=" * 50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ.get("OPENAI_API_KEY")
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    # Build a large JSON payload.
    # Keep max_tokens small to reduce cost; we only care that the proxy does not hang.
    large_text = "A" * 120_000
    payload = {
        "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        "messages": [
            {"role": "system", "content": "Return a short response."},
            {"role": "user", "content": large_text},
        ],
        "max_tokens": 1,
        "stream": False,
    }

    payload_bytes = json.dumps(payload).encode("utf-8")
    print(f"Base URL: {base_url}")
    print(f"Payload size (bytes): {len(payload_bytes)}")
    assert len(payload_bytes) >= 100_000, "payload must be >= 100KB to reproduce the hang"

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # We specifically want the client->proxy leg to be HTTP/2.
    timeout = httpx.Timeout(30.0, connect=10.0)
    with httpx.Client(base_url=base_url, http2=True, verify=ssl_cert, timeout=timeout) as client:
        start = time.time()
        resp = client.post("/chat/completions", headers=headers, json=payload)
        elapsed = time.time() - start

    print(f"Status: {resp.status_code}")
    print(f"HTTP Version: {resp.http_version}")
    print(f"x-upstream-protocol: {resp.headers.get('x-upstream-protocol')}")
    print(f"Elapsed: {elapsed:.2f}s")
    print(f"Body (first 200 chars): {resp.text[:200]!r}")

    assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
    # The exact status code depends on upstream limits/auth, but it must not hang.
    assert resp.status_code in [200, 400, 401, 403, 413, 422], f"Unexpected status: {resp.status_code}"
    assert (
        resp.headers.get("x-upstream-protocol", "").lower() == "h2"
    ), "Expected x-upstream-protocol: h2"

    print("\u2713 HTTP/2 large body test passed (received response headers)")


if __name__ == "__main__":
    test_h2_large_body_request()
