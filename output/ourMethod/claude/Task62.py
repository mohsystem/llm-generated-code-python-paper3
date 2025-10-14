
def parse_and_get_root(json_string: str) -> str:
    if json_string is None:
        raise ValueError("Input cannot be None")
    
    if not isinstance(json_string, str):
        raise TypeError("Input must be a string")
    
    if len(json_string) > 1000000:
        raise ValueError("Input too large")
    
    trimmed = json_string.strip()
    if not trimmed:
        raise ValueError("Empty JSON string")
    
    first_char = trimmed[0]
    
    if first_char == '{':
        return "object"
    elif first_char == '[':
        return "array"
    elif trimmed.startswith('"') and trimmed.endswith('"') and len(trimmed) > 1:
        return "string"
    elif trimmed == "true" or trimmed == "false":
        return "boolean"
    elif trimmed == "null":
        return "null"
    elif is_valid_number(trimmed):
        return "number"
    else:
        raise ValueError("Invalid JSON format")


def is_valid_number(value: str) -> bool:
    if not value:
        return False
    
    try:
        float(value)
        return True
    except ValueError:
        return False


def main():
    test_cases = [
        '{"name":"John","age":30}',
        '[1,2,3,4,5]',
        '"Hello World"',
        '42',
        'true'
    ]
    
    for i, test in enumerate(test_cases, 1):
        try:
            result = parse_and_get_root(test)
            print(f"Test {i}: {result}")
        except Exception as e:
            print(f"Test {i} Error: {e}")


if __name__ == "__main__":
    main()
