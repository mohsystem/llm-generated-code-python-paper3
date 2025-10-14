import base64
import json
from typing import Dict, Any, Optional

def process_request(raw_data: str) -> Optional[Dict[str, Any]]:
    """
    Processes a request by decoding and deserializing the raw data.

    :param raw_data: A UTF-8 string containing Base64 encoded JSON data.
    :return: A dictionary if processing is successful, None otherwise.
    """
    if not isinstance(raw_data, str):
        return None
        
    try:
        # 1. Retrieve raw_data and ensure it is encoded in UTF-8 for b64decode.
        raw_data_bytes = raw_data.encode('utf-8')
        
        # 2. Decode the raw_data using Base64.
        # The 'validate=True' flag helps reject invalid base64 characters.
        decoded_bytes = base64.b64decode(raw_data_bytes, validate=True)
        
        # The decoded data is a JSON string, which needs to be decoded from bytes.
        json_string = decoded_bytes.decode('utf-8')
        
        # 3. Deserialize the decoded data (JSON).
        # 4. Store the deserialized data in a variable.
        data = json.loads(json_string)
        
        # 5. Return the stored data.
        return data
    except (UnicodeDecodeError, TypeError, base64.binascii.Error, json.JSONDecodeError):
        # Catches errors from encoding, base64 decoding, or JSON parsing.
        return None

def main():
    """Main function with test cases."""
    test_cases = [
        # Test Case 1: Valid input
        "eyJ1c2VyIjogInRlc3QiLCAiaWQiOiAxMjMsICJhY3RpdmUiOiB0cnVlfQ==",
        # Test Case 2: Another valid input
        "eyJoZWxsbyI6ICJ3b3JsZCJ9",
        # Test Case 3: Invalid Base64
        "this-is-not-base64",
        # Test Case 4: Valid Base64, but not JSON
        "aGVsbG8gd29ybGQ=", # "hello world"
        # Test Case 5: Empty input
        ""
    ]

    for i, test_case in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        print(f"Input: \"{test_case}\"")
        result = process_request(test_case)
        if result is not None:
            print(f"Output: {json.dumps(result, indent=2)}")
        else:
            print("Output: Processing failed (None)")
        print("--------------------")

if __name__ == "__main__":
    main()