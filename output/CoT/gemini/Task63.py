import base64
import json

def process_request(raw_data: str):
    """
    Processes a request by decoding Base64 and deserializing the resulting JSON.

    Args:
        raw_data: The Base64 encoded UTF-8 string.

    Returns:
        A dictionary representing the deserialized JSON data, or None on failure.
    """
    if not isinstance(raw_data, str):
        print("Error: Input must be a string.")
        return None

    try:
        # 1. Retrieve the raw_data from the request, ensuring it is encoded in UTF-8.
        # The input string is encoded to bytes for the decoder.
        raw_data_bytes = raw_data.encode('utf-8')

        # 2. Decode the raw_data using Base64.
        # The validate=True flag helps in rejecting non-alphabet characters.
        decoded_bytes = base64.b64decode(raw_data_bytes, validate=True)
        
        # 3. Deserialize the decoded data (JSON) into its original format (a dict).
        # The bytes are decoded back to a string for the JSON parser.
        json_string = decoded_bytes.decode('utf-8')
        
        # 4. Store the deserialized data and return it.
        data = json.loads(json_string)
        return data

    except (ValueError, TypeError, base64.binascii.Error) as e:
        # Catches errors from encoding or base64 decoding (e.g., padding error, invalid chars).
        print(f"Error: Invalid Base64 data. {e}")
        return None
    except json.JSONDecodeError as e:
        # Catches errors from json.loads() for malformed JSON.
        print(f"Error: Invalid JSON data. {e}")
        return None
    except UnicodeDecodeError as e:
        # Catches errors if the decoded bytes are not valid UTF-8.
        print(f"Error: Decoded data is not valid UTF-8. {e}")
        return None
    except Exception as e:
        # General exception for any other unexpected errors.
        print(f"An unexpected error occurred: {e}")
        return None

# Main execution block with test cases
if __name__ == "__main__":
    test_cases = [
        # Test Case 1: Simple valid JSON
        "eyJpZCI6IDEyMywgInVzZXIiOiAidGVzdCJ9", # {"id": 123, "user": "test"}
        # Test Case 2: More complex JSON
        "eyJuYW1lIjogIkJvYiIsICJhY3RpdmUiOiB0cnVlLCAicm9sZXMiOiBbImFkbWluIiwgImVkaXRvciJdfQ==", # {"name": "Bob", "active": true, "roles": ["admin", "editor"]}
        # Test Case 3: Empty JSON object
        "e30=", # {}
        # Test Case 4: Invalid Base64 string
        "invalid-base64@#$",
        # Test Case 5: Valid Base64, but not valid JSON
        "VGhpcyBpcyBub3QgSlNPTg==" # "This is not JSON"
    ]

    for i, test_case in enumerate(test_cases):
        print(f"--- Test Case {i + 1} ---")
        print(f"Input: {test_case}")
        result = process_request(test_case)
        if result is not None:
            print(f"Output: {result}")
        else:
            print("Output: Processing failed.")
        print()