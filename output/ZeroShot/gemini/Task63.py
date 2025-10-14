import base64
import json
from typing import Dict, Any, Optional

def process_request(raw_data: str) -> Optional[Dict[str, Any]]:
    """
    Processes a raw request by Base64 decoding and JSON deserializing the data.

    Args:
        raw_data: The Base64 encoded, UTF-8 string from the request.

    Returns:
        A dictionary with the deserialized data, or None on error.
    """
    # SECURITY: Avoid insecure deserialization libraries like `pickle` with untrusted data.
    # The `json` library is safe for this purpose as it does not execute code.
    if not raw_data:
        print("Error: Input data is empty.")
        return None

    try:
        # Step 1: Retrieve raw_data and ensure it's encoded in UTF-8 for decoding.
        raw_data_bytes = raw_data.encode('utf-8')

        # Step 2: Decode the raw_data using Base64.
        # The `validate=True` flag helps reject non-alphabet characters.
        decoded_bytes = base64.b64decode(raw_data_bytes, validate=True)
        
        # Ensure the decoded data is valid UTF-8.
        decoded_string = decoded_bytes.decode('utf-8')
        
        # Step 3: Deserialize the decoded data from JSON into a Python dictionary.
        deserialized_data = json.loads(decoded_string)
        
        # Step 4 & 5: The deserialized data is stored and returned.
        return deserialized_data
        
    except (ValueError, base64.binascii.Error) as e:
        print(f"Error: Invalid Base64 input. {e}")
        return None
    except UnicodeDecodeError as e:
        print(f"Error: Decoded data is not valid UTF-8. {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Failed to deserialize JSON. The decoded data is not valid JSON. {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def main():
    """ Main function with test cases. """
    test_cases = [
        # Test Case 1: Valid JSON data
        "eyJ1c2VyIjogImFkbWluIiwgImlkIjogMTIzfQ==", # Decodes to: {"user": "admin", "id": 123}
        # Test Case 2: Another valid JSON
        "eyJrZXkiOiAidmFsdWUiLCAibnVtYmVyIjogNDJ9", # Decodes to: {"key": "value", "number": 42}
        # Test Case 3: Invalid Base64 string
        "invalid-base64-string",
        # Test Case 4: Valid Base64, but the content is not JSON
        "SGVsbG8gV29ybGQ=", # Decodes to: "Hello World"
        # Test Case 5: Empty string
        ""
    ]

    for i, test_case in enumerate(test_cases, 1):
        print(f"--- Test Case {i} ---")
        print(f"Input: {test_case}")
        result = process_request(test_case)
        if result is not None:
            print(f"Processed Data: {result}")
        else:
            print("Processing failed.")
        print()

if __name__ == "__main__":
    main()