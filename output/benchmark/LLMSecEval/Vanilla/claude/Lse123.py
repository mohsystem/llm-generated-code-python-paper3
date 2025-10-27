
def process_string(input_str):
    if input_str is None or not isinstance(input_str, str):
        return None
    
    # Trim trailing whitespace
    end = len(input_str) - 1
    while end >= 0 and input_str[end].isspace():
        end -= 1
    
    # Trim newlines
    while end >= 0 and input_str[end] in ['\\n', '\\r']:
        end -= 1
    
    # Return the trimmed string (Python strings are immutable and don't need null termination)\n    return input_str[:end + 1]\n\nif __name__ == "__main__":\n    # Test case 1: String with trailing spaces\n    print(f"Test 1: '{process_string('hello world   ')}'")\n    \n    # Test case 2: String with trailing newlines\n    print(f"Test 2: '{process_string('hello world\\\\n\\\\n')}'")\n    \n    # Test case 3: String with trailing spaces and newlines\n    print(f"Test 3: '{process_string('hello world  \\\\n\\\\r ')}'")\n    \n    # Test case 4: String with no trailing whitespace\n    print(f"Test 4: '{process_string('hello world')}'")\n    \n    # Test case 5: Empty string\n    print(f"Test 5: '{process_string('')}'")
