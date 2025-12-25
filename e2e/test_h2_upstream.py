"""
E2E tests for HTTP/2 upstream connections.

This test suite verifies that when clients connect to the proxy using HTTP/2,
the proxy also uses HTTP/2 to connect to the upstream server.
"""

import asyncio
import concurrent.futures
import os
import httpx
from typing import List
from openai import OpenAI
from pydantic import BaseModel


class EntitiesModel(BaseModel):
    attributes: List[str]
    colors: List[str]
    animals: List[str]


def test_h2_upstream_basic():
    """Test basic HTTP/2 upstream connectivity."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 upstream basic connectivity")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    # Use HTTP/2 client
    with httpx.Client(base_url=base_url, http2=True, verify=ssl_cert) as client:
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {api_key}",
            },
        )
        print(f"Status: {resp.status_code}")
        print(f"HTTP Version: {resp.http_version}")

        # Verify we're using HTTP/2 on the client side
        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

    print("\u2713 HTTP/2 upstream basic test passed!")


def test_h2_upstream_streaming():
    """Test HTTP/2 upstream with streaming response."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 upstream streaming")
    print('='*50)

    # Use OpenAI client with HTTP/2
    client = OpenAI(http_client=httpx.Client(http2=True))

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
        chunks_received = 0
        for event in stream:
            if event.type == "response.output_text.delta":
                chunks_received += 1
            elif event.type == "response.completed":
                print("Stream completed")

        final_response = stream.get_final_response()
        print(f"Received {chunks_received} streaming chunks")
        print(f"Final response output count: {len(final_response.output)}")

        # Validate response
        output_text = final_response.output[0].content[0].text
        result = EntitiesModel.model_validate_json(output_text)
        animals_lower = [a.lower() for a in result.animals]
        assert "fox" in animals_lower, f"Expected 'fox' in animals, got: {result.animals}"
        assert "dog" in animals_lower, f"Expected 'dog' in animals, got: {result.animals}"

    print("\u2713 HTTP/2 upstream streaming test passed!")


def test_h2_upstream_multiplexing():
    """Test HTTP/2 connection multiplexing."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 upstream multiplexing")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    # Make multiple concurrent requests over the same HTTP/2 connection
    async def make_async_requests():
        async with httpx.AsyncClient(base_url=base_url, http2=True, verify=ssl_cert, timeout=60) as client:
            tasks = []
            for i in range(5):
                task = client.get(
                    "/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                tasks.append(task)

            responses = await asyncio.gather(*tasks)

            for i, resp in enumerate(responses):
                print(f"  Request {i+1}: Status {resp.status_code}, HTTP Version: {resp.http_version}")
                assert resp.status_code == 200, f"Request {i+1} failed with status {resp.status_code}"
                assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"

    asyncio.run(make_async_requests())
    print("\u2713 HTTP/2 upstream multiplexing test passed!")


def test_h2_upstream_large_request():
    """Test HTTP/2 upstream with larger request bodies."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 upstream with large request")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    # Create a request with a moderately large payload
    large_text = "This is a test sentence. " * 100  # About 2.5KB of text

    with httpx.Client(base_url=base_url, http2=True, verify=ssl_cert, timeout=120) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "Summarize the following text in one sentence."},
                    {"role": "user", "content": large_text}
                ],
                "max_tokens": 100
            }
        )
        print(f"Status: {resp.status_code}")
        print(f"HTTP Version: {resp.http_version}")

        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        # Verify we got a valid response
        data = resp.json()
        assert "choices" in data, "Expected 'choices' in response"
        print(f"Response: {data['choices'][0]['message']['content'][:100]}...")

    print("\u2713 HTTP/2 upstream large request test passed!")


def test_h2_upstream_connection_reuse():
    """Test that HTTP/2 connections are properly reused."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 upstream connection reuse")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    # Make sequential requests and verify they succeed
    # HTTP/2 should reuse the same connection
    with httpx.Client(base_url=base_url, http2=True, verify=ssl_cert, timeout=30) as client:
        for i in range(5):
            resp = client.get(
                "/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            print(f"  Request {i+1}: Status {resp.status_code}")
            assert resp.status_code == 200, f"Request {i+1} failed with status {resp.status_code}"
            assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"

    print("\u2713 HTTP/2 upstream connection reuse test passed!")


def test_h2_upstream_error_handling():
    """Test HTTP/2 upstream error handling (404 from upstream)."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 upstream error handling")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    # Test with invalid endpoint - should get 404 from upstream
    with httpx.Client(base_url=base_url, http2=True, verify=ssl_cert) as client:
        resp = client.get(
            "/v1/nonexistent-endpoint",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        print(f"Invalid endpoint: Status {resp.status_code}")
        print(f"HTTP Version: {resp.http_version}")
        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"

    print("\u2713 HTTP/2 upstream error handling test passed!")


def test_h2_invalid_auth_key():
    """Test that invalid API key returns 401 from proxy (HTTP/2)."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 invalid auth key -> 401")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    with httpx.Client(base_url=base_url, http2=True, verify=ssl_cert, timeout=10) as client:
        # Test with completely invalid key
        resp = client.get(
            "/v1/models",
            headers={"Authorization": "Bearer invalid-key-12345"},
        )
        print(f"  Invalid key: Status {resp.status_code}")
        print(f"  HTTP Version: {resp.http_version}")
        print(f"  Response body: {resp.text}")
        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
        assert "authentication failed" in resp.text.lower(), f"Expected 'authentication failed' in body, got: {resp.text}"

        # Test with missing auth header
        resp = client.get("/v1/models")
        print(f"  Missing auth: Status {resp.status_code}")
        print(f"  HTTP Version: {resp.http_version}")
        print(f"  Response body: {resp.text}")
        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
        assert "authentication failed" in resp.text.lower(), f"Expected 'authentication failed' in body, got: {resp.text}"

    print("\u2713 HTTP/2 invalid auth key test passed!")


def test_h2_upstream_concurrent_streams():
    """Test multiple concurrent HTTP/2 streams."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 upstream concurrent streams")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    def make_request(i):
        with httpx.Client(base_url=base_url, http2=True, verify=ssl_cert, timeout=60) as client:
            resp = client.get(
                "/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            return i, resp.status_code, resp.http_version

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request, i) for i in range(20)]
        success_count = 0
        for future in concurrent.futures.as_completed(futures):
            i, status, http_version = future.result()
            print(f"  Request {i}: Status {status}, HTTP Version: {http_version}")
            assert status == 200, f"Request {i} failed with status {status}"
            assert http_version == "HTTP/2", f"Expected HTTP/2, got {http_version}"
            success_count += 1

    print(f"  Total successful requests: {success_count}/20")
    print("\u2713 HTTP/2 upstream concurrent streams test passed!")


def test_h2_upstream_headers_preservation():
    """Test that headers are properly preserved in HTTP/2 upstream."""
    print(f"\n{'='*50}")
    print("Testing HTTP/2 upstream headers preservation")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]
    ssl_cert = os.environ.get("SSL_CERT_FILE")

    # Add custom headers and verify the request succeeds
    with httpx.Client(base_url=base_url, http2=True, verify=ssl_cert) as client:
        resp = client.get(
            "/v1/models",
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-Custom-Header": "test-value",
                "Accept": "application/json",
                "User-Agent": "openproxy-e2e-test/1.0",
            },
        )
        print(f"Status: {resp.status_code}")
        print(f"HTTP Version: {resp.http_version}")

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert resp.http_version == "HTTP/2", f"Expected HTTP/2, got {resp.http_version}"

    print("\u2713 HTTP/2 upstream headers preservation test passed!")


# Run all tests
if __name__ == "__main__":
    test_h2_upstream_basic()
    test_h2_upstream_streaming()
    test_h2_upstream_multiplexing()
    test_h2_upstream_large_request()
    test_h2_upstream_connection_reuse()
    test_h2_upstream_error_handling()
    test_h2_invalid_auth_key()
    test_h2_upstream_concurrent_streams()
    test_h2_upstream_headers_preservation()

    print("\n" + "="*50)
    print("\u2713 All HTTP/2 upstream tests passed!")
    print("="*50)
