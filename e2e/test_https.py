from typing import List

import httpx
import os
from openai import OpenAI
from pydantic import BaseModel


class EntitiesModel(BaseModel):
    attributes: List[str]
    colors: List[str]
    animals: List[str]


def run_test(client: OpenAI, protocol: str):
    print(f"\n{'='*50}")
    print(f"Testing HTTPS with {protocol}")
    print('='*50)

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
            if event.type == "response.refusal.delta":
                print(event.delta, end="")
            elif event.type == "response.output_text.delta":
                print(event.delta, end="")
            elif event.type == "response.error":
                print(event.error, end="")
            elif event.type == "response.completed":
                print("Completed")

        final_response = stream.get_final_response()
        print(final_response)

        # Parse the output and validate animals
        output_text = final_response.output[0].content[0].text
        result = EntitiesModel.model_validate_json(output_text)
        animals_lower = [a.lower() for a in result.animals]

        assert "fox" in animals_lower, f"Expected 'fox' in animals, got: {result.animals}"
        assert "dog" in animals_lower, f"Expected 'dog' in animals, got: {result.animals}"

        print(f"\u2713 HTTPS + {protocol} test passed!")


def test_no_provider_found_https_http1():
    """Verify 404 and message when no provider matches the Host header over HTTPS HTTP/1.1."""
    print(f"\n{'='*50}")
    print("Testing HTTPS (HTTP/1.1) no-provider-found handling")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]

    # HTTP/1.1 only, to ensure we hit the http/1.1 proxy path
    with httpx.Client(base_url=base_url, http2=False, verify=os.environ.get("SSL_CERT_FILE")) as client:
        resp = client.get(
            "/models",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Host": "no-such-provider.local",
            },
        )

    print("Status:", resp.status_code)
    print("Body:", resp.text)

    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
    assert resp.text.strip().lower() == "no provider found", f"Unexpected body: {resp.text!r}"

    print("\u2713 HTTPS HTTP/1.1 no-provider-found test passed!")


# Test with HTTP/1.1
client_http1 = OpenAI(http_client=httpx.Client(http2=False))
run_test(client_http1, "HTTP/1.1")

# Test with HTTP/2
client_http2 = OpenAI(http_client=httpx.Client(http2=True))
run_test(client_http2, "HTTP/2")

# Also verify 404 handling when no provider is found over HTTPS HTTP/1.1
test_no_provider_found_https_http1()

print("\n" + "="*50)
print("\u2713 All HTTPS tests passed!")
print("="*50)
