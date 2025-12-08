"""
E2E tests for host path prefix routing.

This tests the scenario where providers are configured with a path prefix in the host,
e.g., `host: path-test.local/openai`. The proxy should:
1. Match requests based on both host and path prefix
2. Strip the path prefix before forwarding to the backend

Test configuration in e2e.yml:
  - host: path-test.local/openai -> routes /openai/* requests
  - host: nested-path.local/api/v1 -> routes /api/v1/* requests
"""

from typing import List
import httpx
import os

from openai import OpenAI
from pydantic import BaseModel


class EntitiesModel(BaseModel):
    attributes: List[str]
    colors: List[str]
    animals: List[str]


def get_proxy_config():
    """Get proxy configuration from environment variables."""
    host = os.environ.get("PROXY_HOST", "localhost")
    https_port = os.environ.get("PROXY_HTTPS_PORT", "8443")
    http_port = os.environ.get("PROXY_HTTP_PORT", "8080")
    api_key = os.environ["OPENAI_API_KEY"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")
    return {
        "host": host,
        "https_port": https_port,
        "http_port": http_port,
        "api_key": api_key,
        "ssl_cert": ssl_cert,
    }


def test_host_path_prefix_https_http1():
    """Test host path prefix routing over HTTPS with HTTP/1.1."""
    print(f"\n{'='*60}")
    print("Testing Host Path Prefix: HTTPS + HTTP/1.1 + /openai prefix")
    print("=" * 60)

    config = get_proxy_config()
    # Connect to the actual proxy host but use Host header for routing
    # The proxy routes based on Host header, not the actual connection host
    base_url = f"https://{config['host']}:{config['https_port']}/openai/v1"

    # Create a custom transport that sets the Host header
    class HostOverrideTransport(httpx.HTTPTransport):
        def handle_request(self, request):
            # Override Host header to match our path-prefix provider
            request.headers["Host"] = "path-test.local"
            return super().handle_request(request)

    client = OpenAI(
        base_url=base_url,
        api_key=config["api_key"],
        http_client=httpx.Client(
            http2=False,
            verify=config["ssl_cert"],
            transport=HostOverrideTransport(verify=config["ssl_cert"]),
        ),
    )

    with client.responses.stream(
        model="gpt-4.1",
        input=[
            {"role": "system", "content": "Extract entities from the input text"},
            {
                "role": "user",
                "content": "The quick brown fox jumps over the lazy dog with piercing blue eyes",
            },
        ],
        text_format=EntitiesModel,
    ) as stream:
        for event in stream:
            if event.type == "response.output_text.delta":
                print(event.delta, end="")
            elif event.type == "response.completed":
                print("\nCompleted")

        final_response = stream.get_final_response()
        output_text = final_response.output[0].content[0].text
        result = EntitiesModel.model_validate_json(output_text)
        animals_lower = [a.lower() for a in result.animals]

        assert "fox" in animals_lower, f"Expected 'fox' in animals, got: {result.animals}"
        assert "dog" in animals_lower, f"Expected 'dog' in animals, got: {result.animals}"

    print("\u2713 HTTPS + HTTP/1.1 + /openai prefix test passed!")


def test_host_path_prefix_https_http2():
    """Test host path prefix routing over HTTPS with HTTP/2."""
    print(f"\n{'='*60}")
    print("Testing Host Path Prefix: HTTPS + HTTP/2 + /openai prefix")
    print("=" * 60)

    config = get_proxy_config()
    base_url = f"https://{config['host']}:{config['https_port']}/openai/v1"

    # For HTTP/2, we need to use headers parameter on each request
    # since HTTP/2 uses :authority pseudo-header
    # We'll use a custom event hook to set the host header
    def set_host_header(request):
        request.headers["Host"] = "path-test.local"

    client = OpenAI(
        base_url=base_url,
        api_key=config["api_key"],
        http_client=httpx.Client(
            http2=True,
            verify=config["ssl_cert"],
            event_hooks={"request": [set_host_header]},
        ),
    )

    with client.responses.stream(
        model="gpt-4.1",
        input=[
            {"role": "system", "content": "Extract entities from the input text"},
            {
                "role": "user",
                "content": "The quick brown fox jumps over the lazy dog with piercing blue eyes",
            },
        ],
        text_format=EntitiesModel,
    ) as stream:
        for event in stream:
            if event.type == "response.output_text.delta":
                print(event.delta, end="")
            elif event.type == "response.completed":
                print("\nCompleted")

        final_response = stream.get_final_response()
        output_text = final_response.output[0].content[0].text
        result = EntitiesModel.model_validate_json(output_text)
        animals_lower = [a.lower() for a in result.animals]

        assert "fox" in animals_lower, f"Expected 'fox' in animals, got: {result.animals}"
        assert "dog" in animals_lower, f"Expected 'dog' in animals, got: {result.animals}"

    print("\u2713 HTTPS + HTTP/2 + /openai prefix test passed!")


def test_host_path_prefix_http():
    """Test host path prefix routing over HTTP."""
    print(f"\n{'='*60}")
    print("Testing Host Path Prefix: HTTP + /openai prefix")
    print("=" * 60)

    config = get_proxy_config()
    base_url = f"http://{config['host']}:{config['http_port']}/openai/v1"

    class HostOverrideTransport(httpx.HTTPTransport):
        def handle_request(self, request):
            request.headers["Host"] = "path-test.local"
            return super().handle_request(request)

    client = OpenAI(
        base_url=base_url,
        api_key=config["api_key"],
        http_client=httpx.Client(
            http2=False,
            transport=HostOverrideTransport(),
        ),
    )

    with client.responses.stream(
        model="gpt-4.1",
        input=[
            {"role": "system", "content": "Extract entities from the input text"},
            {
                "role": "user",
                "content": "The quick brown fox jumps over the lazy dog with piercing blue eyes",
            },
        ],
        text_format=EntitiesModel,
    ) as stream:
        for event in stream:
            if event.type == "response.output_text.delta":
                print(event.delta, end="")
            elif event.type == "response.completed":
                print("\nCompleted")

        final_response = stream.get_final_response()
        output_text = final_response.output[0].content[0].text
        result = EntitiesModel.model_validate_json(output_text)
        animals_lower = [a.lower() for a in result.animals]

        assert "fox" in animals_lower, f"Expected 'fox' in animals, got: {result.animals}"
        assert "dog" in animals_lower, f"Expected 'dog' in animals, got: {result.animals}"

    print("\u2713 HTTP + /openai prefix test passed!")


def test_nested_path_prefix_https():
    """Test nested path prefix routing (e.g., /api/v1) over HTTPS."""
    print(f"\n{'='*60}")
    print("Testing Host Path Prefix: HTTPS + /api/v1 nested prefix")
    print("=" * 60)

    config = get_proxy_config()
    # Use nested path prefix /api/v1 - requests to /api/v1/v1/* should be routed
    # The /api/v1 prefix should be stripped, so backend receives /v1/*
    base_url = f"https://{config['host']}:{config['https_port']}/api/v1/v1"

    def set_host_header(request):
        request.headers["Host"] = "nested-path.local"

    client = OpenAI(
        base_url=base_url,
        api_key=config["api_key"],
        http_client=httpx.Client(
            http2=True,
            verify=config["ssl_cert"],
            event_hooks={"request": [set_host_header]},
        ),
    )

    with client.responses.stream(
        model="gpt-4.1",
        input=[
            {"role": "system", "content": "Extract entities from the input text"},
            {
                "role": "user",
                "content": "The quick brown fox jumps over the lazy dog with piercing blue eyes",
            },
        ],
        text_format=EntitiesModel,
    ) as stream:
        for event in stream:
            if event.type == "response.output_text.delta":
                print(event.delta, end="")
            elif event.type == "response.completed":
                print("\nCompleted")

        final_response = stream.get_final_response()
        output_text = final_response.output[0].content[0].text
        result = EntitiesModel.model_validate_json(output_text)
        animals_lower = [a.lower() for a in result.animals]

        assert "fox" in animals_lower, f"Expected 'fox' in animals, got: {result.animals}"
        assert "dog" in animals_lower, f"Expected 'dog' in animals, got: {result.animals}"

    print("\u2713 HTTPS + /api/v1 nested prefix test passed!")


def test_nested_path_prefix_http():
    """Test nested path prefix routing (e.g., /api/v1) over HTTP."""
    print(f"\n{'='*60}")
    print("Testing Host Path Prefix: HTTP + /api/v1 nested prefix")
    print("=" * 60)

    config = get_proxy_config()
    base_url = f"http://{config['host']}:{config['http_port']}/api/v1/v1"

    class HostOverrideTransport(httpx.HTTPTransport):
        def handle_request(self, request):
            request.headers["Host"] = "nested-path.local"
            return super().handle_request(request)

    client = OpenAI(
        base_url=base_url,
        api_key=config["api_key"],
        http_client=httpx.Client(
            http2=False,
            transport=HostOverrideTransport(),
        ),
    )

    with client.responses.stream(
        model="gpt-4.1",
        input=[
            {"role": "system", "content": "Extract entities from the input text"},
            {
                "role": "user",
                "content": "The quick brown fox jumps over the lazy dog with piercing blue eyes",
            },
        ],
        text_format=EntitiesModel,
    ) as stream:
        for event in stream:
            if event.type == "response.output_text.delta":
                print(event.delta, end="")
            elif event.type == "response.completed":
                print("\nCompleted")

        final_response = stream.get_final_response()
        output_text = final_response.output[0].content[0].text
        result = EntitiesModel.model_validate_json(output_text)
        animals_lower = [a.lower() for a in result.animals]

        assert "fox" in animals_lower, f"Expected 'fox' in animals, got: {result.animals}"
        assert "dog" in animals_lower, f"Expected 'dog' in animals, got: {result.animals}"

    print("\u2713 HTTP + /api/v1 nested prefix test passed!")


def test_path_prefix_no_match_https():
    """Test that requests with non-matching path prefix return 404."""
    print(f"\n{'='*60}")
    print("Testing Host Path Prefix: HTTPS + non-matching path returns 404")
    print("=" * 60)

    config = get_proxy_config()
    base_url = f"https://{config['host']}:{config['https_port']}"

    with httpx.Client(base_url=base_url, http2=False, verify=config["ssl_cert"]) as client:
        # Request to /nonexistent/v1/models with a host that has path prefix
        # but the path doesn't match the prefix
        resp = client.get(
            "/wrongprefix/v1/models",
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Host": "path-test.local",  # This host expects /openai prefix
            },
        )

        print(f"Status: {resp.status_code}")
        print(f"Body: {resp.text[:200] if len(resp.text) > 200 else resp.text}")

        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
        assert "no provider found" in resp.text.lower(), f"Unexpected body: {resp.text}"

    print("\u2713 Non-matching path prefix returns 404 test passed!")


def test_path_prefix_no_match_http():
    """Test that requests with non-matching path prefix return 404 over HTTP."""
    print(f"\n{'='*60}")
    print("Testing Host Path Prefix: HTTP + non-matching path returns 404")
    print("=" * 60)

    config = get_proxy_config()
    base_url = f"http://{config['host']}:{config['http_port']}"

    with httpx.Client(base_url=base_url, http2=False) as client:
        resp = client.get(
            "/wrongprefix/v1/models",
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Host": "path-test.local",  # This host expects /openai prefix
            },
        )

        print(f"Status: {resp.status_code}")
        print(f"Body: {resp.text[:200] if len(resp.text) > 200 else resp.text}")

        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
        assert "no provider found" in resp.text.lower(), f"Unexpected body: {resp.text}"

    print("\u2713 HTTP non-matching path prefix returns 404 test passed!")


def test_path_prefix_exact_match():
    """Test that path prefix matching requires exact prefix match."""
    print(f"\n{'='*60}")
    print("Testing Host Path Prefix: exact prefix matching")
    print("=" * 60)

    config = get_proxy_config()
    base_url = f"https://{config['host']}:{config['https_port']}"

    with httpx.Client(base_url=base_url, http2=False, verify=config["ssl_cert"]) as client:
        # /openai-extra should NOT match /openai prefix (requires / or end after prefix)
        resp = client.get(
            "/openai-extra/v1/models",
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Host": "path-test.local",  # This host expects /openai prefix
            },
        )

        print(f"Status: {resp.status_code}")

        # This should return 404 because /openai-extra doesn't match /openai
        # (the code checks that after the prefix there's either '/' or end of path)
        assert resp.status_code == 404, f"Expected 404 for /openai-extra, got {resp.status_code}"

    print("\u2713 Exact prefix matching test passed!")


if __name__ == "__main__":
    # Run HTTPS tests
    test_host_path_prefix_https_http1()
    test_host_path_prefix_https_http2()
    test_nested_path_prefix_https()
    test_path_prefix_no_match_https()
    test_path_prefix_exact_match()

    # Run HTTP tests
    test_host_path_prefix_http()
    test_nested_path_prefix_http()
    test_path_prefix_no_match_http()

    print("\n" + "=" * 60)
    print("\u2713 All Host Path Prefix tests passed!")
    print("=" * 60)
