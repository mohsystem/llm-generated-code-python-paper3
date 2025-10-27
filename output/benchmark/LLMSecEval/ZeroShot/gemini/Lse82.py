# This code simulates the backend logic of a web route that processes a JSON payload.
# It is designed to be run as a single file and uses only standard libraries.

import json
from urllib.parse import parse_qs

def process_api_request(query_string: str) -> str:
    """
    Simulates processing a request to an /api endpoint. It extracts a 'payload'
    parameter from the query string, parses it as JSON, and returns the value 
    associated with the 'name' key.
    
    Args:
        query_string: The query string from the URL (e.g., "payload=%7B...%7D").
        
    Returns:
        The value of the 'name' key if found, otherwise an error message.
    """
    try:
        # parse_qs automatically URL-decodes values
        params = parse_qs(query_string)
        
        if 'payload' not in params:
            return "Error: 'payload' parameter not found."
            
        # parse_qs returns a list of values for each key; get the first one
        payload_list = params.get('payload', [])
        if not payload_list or not payload_list[0]:
            return "Error: 'payload' parameter is empty."
        
        payload_str = payload_list[0]
        data = json.loads(payload_str)

        if not isinstance(data, dict):
            return "Error: Payload is not a JSON object."

        name = data.get("name")

        if name is None:
            return "Error: 'name' key not found in payload."
        
        if not isinstance(name, str):
            return "Error: 'name' value is not a string."

        return name
        
    except json.JSONDecodeError:
        return "Error: Malformed JSON in payload."
    except Exception:
        # Catch-all for other unexpected issues
        return "Error: An unexpected error occurred."


def main():
    """Main function with test cases for the process_api_request function."""
    test_cases = [
        # 1. Valid case with a 'name' key
        "payload=%7B%22name%22%3A%22Alice%22%2C%20%22id%22%3A123%7D",
        # 2. Valid JSON but missing the 'name' key
        "payload=%7B%22id%22%3A456%7D",
        # 3. Malformed JSON (extra comma)
        "payload=%7B%22name%22%3A%22Bob%22%2C%7D",
        # 4. Query string without a 'payload' parameter
        "other_param=abc&another=123",
        # 5. 'name' key exists but its value is not a string
        "payload=%7B%22name%22%3A12345%7D"
    ]

    print("Running test cases...")
    for i, test_str in enumerate(test_cases):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Input: {test_str}")
        result = process_api_request(test_str)
        print(f"Output: {result}")

if __name__ == "__main__":
    main()