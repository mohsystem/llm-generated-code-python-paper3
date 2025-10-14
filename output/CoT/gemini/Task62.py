import json

def find_root_element(json_string):
    """
    Parses the JSON string using Python's built-in json library to identify
    the root element's type. This is a robust way to validate the entire JSON structure.

    Args:
        json_string: The string representation of the JSON document.

    Returns:
        "Object", "Array", or "Invalid" based on the root element.
    """
    if not isinstance(json_string, str):
        return "Invalid"
        
    try:
        # Attempt to parse the entire JSON string
        data = json.loads(json_string)
        
        # Check the type of the parsed root element
        if isinstance(data, dict):
            return "Object"
        elif isinstance(data, list):
            return "Array"
        else:
            # Other valid JSON types like string, number, boolean, null are not considered
            # as root "documents" for this problem's context.
            return "Invalid"
    except json.JSONDecodeError:
        # The string is not a valid JSON document
        return "Invalid"

def main():
    """ Main function with test cases """
    test_cases = [
        "  { \"name\": \"John\", \"age\": 30 }  ",
        "[ \"apple\", \"banana\", \"cherry\" ]",
        "   ",
        "this is not json",
        "{ \"incomplete\": \"json\""
    ]

    print("Python Test Cases:")
    for test_case in test_cases:
        print(f'Input: "{test_case}" -> Output: {find_root_element(test_case)}')
    # Test with non-string input
    print(f'Input: None -> Output: {find_root_element(None)}')

if __name__ == "__main__":
    main()