import json
from typing import Any

def get_root_element_type(json_string: str) -> str:
    """
    Parses a JSON string and returns the type of its root element.
    Uses Python's built-in, safe JSON parser.
    """
    if not isinstance(json_string, str):
        return "invalid"
        
    try:
        # Trim whitespace before parsing, as loads() is strict with leading/trailing non-JSON content
        trimmed_string = json_string.strip()
        if not trimmed_string:
            return "invalid"
            
        data: Any = json.loads(trimmed_string)
        if isinstance(data, dict):
            return "object"
        elif isinstance(data, list):
            return "array"
        elif isinstance(data, str):
            return "string"
        elif isinstance(data, bool):
            return "boolean"
        elif isinstance(data, (int, float)):
            return "number"
        elif data is None:
            return "null"
        else:
            # This case should not be reached with a standard JSON parser
            return "invalid"
    except json.JSONDecodeError:
        return "invalid"

def main():
    """Main function with test cases."""
    test_cases = [
        ("  { \"key\": \"value\" }  ", "object"),
        (" [1, 2, 3] ", "array"),
        ("\"a string\"", "string"),
        ("123.45", "number"),
        ("false", "boolean"),
        ("  null  ", "null"),
        ("{malformed}", "invalid"),
        ("", "invalid")
    ]

    print("Running Python tests...")
    for i, (input_str, expected) in enumerate(test_cases):
        result = get_root_element_type(input_str)
        status = "PASS" if result == expected else "FAIL"
        print(f"Test Case {i + 1}: -> {result} (Expected: {expected}) -> {status}")

if __name__ == "__main__":
    main()