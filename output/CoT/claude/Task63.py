
import base64
import json
from typing import Any, Union, Dict, List

MAX_DATA_SIZE = 1024 * 1024  # 1MB limit

def process_request(raw_data: str) -> Union[Dict, List, Any]:
    """\n    Securely process incoming request data.\n    \n    Args:\n        raw_data: Base64 encoded UTF-8 string\n        \n    Returns:\n        Deserialized data object\n        \n    Raises:\n        ValueError: If data is invalid or exceeds size limits\n        TypeError: If input is not a string\n    """
    if not isinstance(raw_data, str):
        raise TypeError("Raw data must be a string")
    
    if not raw_data or len(raw_data.strip()) == 0:
        raise ValueError("Raw data cannot be null or empty")
    
    # Validate data size to prevent DoS attacks
    if len(raw_data) > MAX_DATA_SIZE:
        raise ValueError("Data exceeds maximum allowed size")
    
    try:
        # Ensure UTF-8 encoding
        utf8_bytes = raw_data.encode('utf-8')
        
        # Decode Base64 with validation
        decoded_bytes = base64.b64decode(utf8_bytes, validate=True)
        
        # Validate decoded size
        if len(decoded_bytes) > MAX_DATA_SIZE:
            raise ValueError("Decoded data exceeds maximum allowed size")
        
        # Convert to UTF-8 string
        decoded_string = decoded_bytes.decode('utf-8')
        
        # Validate JSON structure before deserialization
        if not decoded_string.strip():
            raise ValueError("Decoded data is empty")
        
        # Deserialize JSON safely
        deserialized_data = json.loads(decoded_string)
        
        return deserialized_data
        
    except base64.binascii.Error as e:
        print(f"Base64 decoding error: {e}")
        raise ValueError("Invalid Base64 encoded data") from e
    except json.JSONDecodeError as e:
        print(f"JSON deserialization error: {e}")
        raise ValueError("Invalid JSON data") from e
    except UnicodeDecodeError as e:
        print(f"UTF-8 decoding error: {e}")
        raise ValueError("Invalid UTF-8 encoding") from e
    except Exception as e:
        print(f"Processing error: {e}")
        raise RuntimeError("Error processing request") from e


def main():
    print("Testing Task63 - Secure Request Processing\\n")
    
    # Test Case 1: Valid JSON object
    try:
        test_data1 = base64.b64encode('{"name":"John","age":30}'.encode('utf-8')).decode('utf-8')
        result1 = process_request(test_data1)
        print(f"Test 1 - Valid JSON: {result1}")
    except Exception as e:
        print(f"Test 1 Failed: {e}")
    
    # Test Case 2: Valid JSON array
    try:
        test_data2 = base64.b64encode('["item1","item2","item3"]'.encode('utf-8')).decode('utf-8')
        result2 = process_request(test_data2)
        print(f"Test 2 - Valid JSON Array: {result2}")
    except Exception as e:
        print(f"Test 2 Failed: {e}")
    
    # Test Case 3: Nested JSON
    try:
        test_data3 = base64.b64encode('{"user":{"id":123,"status":"active"}}'.encode('utf-8')).decode('utf-8')
        result3 = process_request(test_data3)
        print(f"Test 3 - Nested JSON: {result3}")
    except Exception as e:
        print(f"Test 3 Failed: {e}")
    
    # Test Case 4: Invalid Base64
    try:
        test_data4 = "Invalid@Base64!Data"
        result4 = process_request(test_data4)
        print(f"Test 4 - Invalid Base64: {result4}")
    except Exception as e:
        print(f"Test 4 Failed (Expected): {e}")
    
    # Test Case 5: Invalid JSON
    try:
        test_data5 = base64.b64encode('{invalid json}'.encode('utf-8')).decode('utf-8')
        result5 = process_request(test_data5)
        print(f"Test 5 - Invalid JSON: {result5}")
    except Exception as e:
        print(f"Test 5 Failed (Expected): {e}")


if __name__ == "__main__":
    main()
