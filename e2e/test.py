from typing import List

import httpx
from openai import OpenAI
from pydantic import BaseModel


class EntitiesModel(BaseModel):
    attributes: List[str]
    colors: List[str]
    animals: List[str]


# Force HTTP/1.1 to avoid HTTP/2 protocol issues
client = OpenAI(http_client=httpx.Client(http2=False))

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
            # print(event.response.output)

    final_response = stream.get_final_response()
    print(final_response)

    # Parse the output and validate animals
    output_text = final_response.output[0].content[0].text
    result = EntitiesModel.model_validate_json(output_text)
    animals_lower = [a.lower() for a in result.animals]

    assert "fox" in animals_lower, f"Expected 'fox' in animals, got: {result.animals}"
    assert "dog" in animals_lower, f"Expected 'dog' in animals, got: {result.animals}"

    print("✓ All assertions passed!")
