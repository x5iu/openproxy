"""E2E test for: HTTP/2 client -> openproxy -> HTTP/1.1 upstream fallback.

This specifically guards against a regression where the fallback path re-parses
(or otherwise re-selects) the provider using the upstream Host header (endpoint),
causing "No provider found" when provider.host != provider.endpoint.

Expected setup (as in .github/workflows/e2e.yml):
- openproxy is already running with a provider like:
    host: h1-fallback.localhost:8443
    endpoint: localhost
    port: 9001
    tls: false
- an upstream HTTP/1.1 echo server is listening on 127.0.0.1:9001
"""

import os

import httpx


def _proxy_verify_param() -> str | bool:
    # httpx verify param can be a CA bundle path or a boolean.
    ca = os.environ.get("SSL_CERT_FILE")
    return ca if ca else False


def _make_h2_request(client: httpx.Client, method: str, url: str, authority: str, auth_key: str, **kwargs):
    headers = kwargs.pop("headers", {})
    headers = {
        **headers,
        "Authorization": f"Bearer {auth_key}",
        # "Host" is not used for routing in HTTP/2, but keep it for debugging.
        "Host": authority,
    }

    return client.request(
        method,
        url,
        headers=headers,
        # Force :authority for HTTP/2 routing.
        extensions={"authority": authority},
        **kwargs,
    )


def test_h2_client_to_h1_upstream_fallback():
    proxy_host = os.environ.get("PROXY_HOST", "localhost")
    https_port = int(os.environ.get("PROXY_HTTPS_PORT", "8443"))

    # In the workflow we pass PROXY_AUTH_KEY. For compatibility with other scripts,
    # allow OPENAI_API_KEY as fallback.
    auth_key = os.environ.get("PROXY_AUTH_KEY") or os.environ.get("OPENAI_API_KEY")
    if not auth_key:
        raise RuntimeError("Missing PROXY_AUTH_KEY (or OPENAI_API_KEY) env var")

    authority = os.environ.get("FALLBACK_AUTHORITY", f"h1-fallback.localhost:{https_port}")

    base_url = f"https://{proxy_host}:{https_port}"

    with httpx.Client(http2=True, verify=_proxy_verify_param(), timeout=30.0) as client:
        # GET
        resp = _make_h2_request(client, "GET", f"{base_url}/test-fallback", authority, auth_key)
        print("GET status:", resp.status_code)
        print("GET HTTP version:", resp.http_version)
        print("GET x-upstream-protocol:", resp.headers.get("x-upstream-protocol"))
        print("GET body:", resp.text[:200] if len(resp.text) > 200 else resp.text)

        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}; body={resp.text!r}"
        assert (
            resp.headers.get("x-upstream-protocol", "").lower() == "http/1.1"
        ), "Expected x-upstream-protocol: http/1.1"

        data = resp.json()
        assert data.get("fallback") == "success", f"Unexpected response: {data}"
        assert data.get("path") == "/test-fallback", f"Unexpected path: {data}"

        # POST
        resp = _make_h2_request(
            client,
            "POST",
            f"{base_url}/test-fallback-post",
            authority,
            auth_key,
            json={"ping": "pong"},
        )
        print("POST status:", resp.status_code)
        print("POST HTTP version:", resp.http_version)
        print("POST x-upstream-protocol:", resp.headers.get("x-upstream-protocol"))
        print("POST body:", resp.text[:200] if len(resp.text) > 200 else resp.text)

        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}; body={resp.text!r}"
        assert (
            resp.headers.get("x-upstream-protocol", "").lower() == "http/1.1"
        ), "Expected x-upstream-protocol: http/1.1"

        data = resp.json()
        assert data.get("fallback") == "success", f"Unexpected response: {data}"
        assert data.get("path") == "/test-fallback-post", f"Unexpected path: {data}"


if __name__ == "__main__":
    # Keep a single entry point for the workflow (python test_*.py).
    test_h2_client_to_h1_upstream_fallback()
    print("\n" + "=" * 50)
    print("\u2713 H2 client -> H1 upstream fallback test passed!")
    print("=" * 50)
