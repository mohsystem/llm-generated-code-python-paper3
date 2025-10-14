import json
from typing import Any, Optional

def get_json_root(json_string: str) -> Optional[Any]:
    """
    Parses a JSON string and returns its root element.
    This function uses Python's built-in, secure json library, which is
    hardened against common vulnerabilities like "billion laughs" attacks.

    :param json_string: The JSON string to parse.
    :return: The root element (dict, list, str, int, etc.) or None if parsing fails.
    """
    if not isinstance(json_string, str) or not json_string.strip():
        print("Error: Input must be a non-empty string.")
        return None
    try:
        # json.loads is the standard, secure way to parse JSON in Python.
        root_element = json.loads(json_string)
        return root_element
    except json.JSONDecodeError:
        # Catching the specific decode error prevents crashing on malformed
        # input and allows for graceful failure.
        print("Error parsing JSON string: Invalid syntax.")
        return None

def main():
    """Main function to run test cases."""
    test_cases = [
        # 1. Valid JSON object
        '{"name": "John Doe", "age": 30, "isStudent": false, "courses": ["Math", "Science"]}',
        # 2. Valid JSON array
        '[1, "test", true, null, {"key": "value"}]',
        # 3. Valid JSON primitive (string)
        '"Hello, Secure World!"',
        # 4. Valid JSON primitive (number)
        '123.456',
        # 5. Invalid JSON string (malformed)
        '{"name": "Jane Doe", "age":}'
    ]

    for i, test_case in enumerate(test_cases):
        print(f"--- Test Case {i + 1} ---")
        print(f"Input: {test_case}")
        root_element = get_json_root(test_case)
        
        if root_element is not None:
            print(f"Root Element Type: {type(root_element).__name__}")
            # The repr() gives a developer-friendly representation
            print(f"Parsed Output: {repr(root_element)}")
        else:
            print("Failed to parse JSON.")
        print()

if __name__ == "__main__":
    main()