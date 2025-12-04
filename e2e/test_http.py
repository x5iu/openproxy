from typing import List

import httpx
import os
from openai import OpenAI
from pydantic import BaseModel


class EntitiesModel(BaseModel):
    attributes: List[str]
    colors: List[str]
    animals: List[str]


def run_test(client: OpenAI):
    print(f"\n{'='*50}")
    print("Testing HTTP (no TLS)")
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

        print("\u2713 HTTP (no TLS) test passed!")


def test_no_provider_found_http():
    """Verify 404 and message when no provider matches the Host header."""
    print(f"\n{'='*50}")
    print("Testing HTTP no-provider-found handling")
    print('='*50)

    base_url = os.environ["OPENAI_BASE_URL"]
    api_key = os.environ["OPENAI_API_KEY"]

    with httpx.Client(base_url=base_url, http2=False) as client:
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

    print("\u2713 HTTP no-provider-found test passed!")


# Test with HTTP/1.1 (HTTP without TLS only supports HTTP/1.1)
client = OpenAI(http_client=httpx.Client(http2=False))
run_test(client)

test_no_provider_found_http()

print("\n" + "="*50)
print("\u2713 All HTTP tests passed!")
print("="*50)
