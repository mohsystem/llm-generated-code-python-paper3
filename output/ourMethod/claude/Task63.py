
import base64
import json
from typing import Any, Union

MAX_INPUT_SIZE = 1024 * 1024  # 1MB limit


def process_request(raw_data: str) -> Union[dict, list, str, int, float, bool, None]:
    """\n    Process incoming request by decoding and deserializing data.\n    \n    Args:\n        raw_data: Base64 encoded UTF-8 string\n        \n    Returns:\n        Deserialized data structure\n        \n    Raises:\n        ValueError: If input is invalid\n    """
    if not raw_data or not isinstance(raw_data, str):
        raise ValueError("Raw data must be a non-empty string")
    
    if len(raw_data) > MAX_INPUT_SIZE:
        raise ValueError("Input exceeds maximum size limit")
    
    # Ensure UTF-8 encoding
    try:
        utf8_bytes = raw_data.encode('utf-8')
        utf8_string = utf8_bytes.decode('utf-8')
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        raise ValueError(f"Invalid UTF-8 encoding: {e}")
    
    # Decode Base64
    try:
        decoded_bytes = base64.b64decode(utf8_string, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid Base64 input: {e}")
    
    if len(decoded_bytes) > MAX_INPUT_SIZE:
        raise ValueError("Decoded data exceeds maximum size limit")
    
    # Convert decoded bytes to string
    try:
        decoded_string = decoded_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise ValueError(f"Decoded data is not valid UTF-8: {e}")
    
    # Deserialize JSON safely
    try:
        deserialized_data = json.loads(decoded_string)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
    
    return deserialized_data


def main() -> None:
    """Test the process_request function with various inputs."""
    test_cases = [
        ('{"name":"John","age":30}', "Valid JSON object"),
        ('[1,2,3,4,5]', "Valid JSON array"),
        ('{"user":{"id":1,"name":"Alice"}}', "Nested JSON"),
        ('"Hello World"', "Simple string value"),
        ('42', "Number value")
    ]
    
    for i, (test_data, description) in enumerate(test_cases, 1):
        try:
            encoded = base64.b64encode(test_data.encode('utf-8')).decode('utf-8')
            result = process_request(encoded)
            print(f"Test {i} ({description}): {result}")
        except Exception as e:
            print(f"Test {i} error: {e}")


if __name__ == "__main__":
    main()
