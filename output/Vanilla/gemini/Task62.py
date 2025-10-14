import json

def get_root_element_type(json_string):
    """
    Parses the provided string to identify the type of the root JSON element.

    :param json_string: The string representing a JSON document.
    :return: A string indicating the root element's type ("Object", "Array", "String",
             "Number", "Boolean", "Null", or "Invalid").
    """
    if not isinstance(json_string, str):
        return "Invalid"
    
    trimmed = json_string.strip()
    
    if not trimmed:
        return "Invalid"

    # Using the built-in json library is the most robust way in Python
    try:
        data = json.loads(trimmed)
        if isinstance(data, dict):
            return "Object"
        elif isinstance(data, list):
            return "Array"
        elif isinstance(data, str):
            return "String"
        elif isinstance(data, (int, float)):
            return "Number"
        elif isinstance(data, bool):
            return "Boolean"
        elif data is None:
            return "Null"
        else:
            return "Invalid" # Should not be reached with standard JSON
    except json.JSONDecodeError:
        # Fallback for strings that are not valid JSON but might match simple types
        # This part handles cases like a bare number "123" without full JSON parsing
        if (trimmed.startswith('{') and trimmed.endswith('}')) or \
           (trimmed.startswith('[') and trimmed.endswith(']')):
             # If it looks like an object/array but failed to parse, it's invalid
             return "Invalid"

        # Check for simple types if full parsing fails
        first_char = trimmed[0]
        if first_char == '"' and trimmed.endswith('"'):
            return "String"
        if trimmed == 'true' or trimmed == 'false':
            return "Boolean"
        if trimmed == 'null':
            return "Null"
        try:
            float(trimmed)
            return "Number"
        except ValueError:
            return "Invalid"

def main():
    test_cases = [
        "  { \"name\": \"John\", \"age\": 30 }  ",  # Test case 1: Object
        "[1, \"apple\", true, null]",               # Test case 2: Array
        "\"This is a root string.\"",               # Test case 3: String
        "  -123.45e6  ",                           # Test case 4: Number
        "null"                                      # Test case 5: Null
    ]
    
    print("Running Python Test Cases:")
    for i, json_str in enumerate(test_cases, 1):
        result = get_root_element_type(json_str)
        print(f'Test Case {i}: "{json_str}" -> {result}')

if __name__ == "__main__":
    main()