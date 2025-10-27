
def trim_string(input_str):
    # Check if exactly one argument is provided (handled by function signature)
    if input_str is None:
        return None
    
    # Check if the argument is a string
    if not isinstance(input_str, str):
        return None
    
    # Convert to list for manipulation
    chars = list(input_str)
    
    # Trim trailing whitespace
    end_index = len(chars) - 1
    while end_index >= 0 and chars[end_index].isspace():
        end_index -= 1
    
    # Trim newlines from the end
    while end_index >= 0 and chars[end_index] in ['\\n', '\\r']:
        end_index -= 1
    
    # Return the trimmed string (null termination is automatic in Python)
    return ''.join(chars[:end_index + 1])


if __name__ == "__main__":
    # Test cases
    print(f"Test 1: '{trim_string('hello world   ')}'")
    print(f"Test 2: '{trim_string('test\\\\n\\\\n')}'")
    print(f"Test 3: '{trim_string('spaces and newlines  \\\\n\\\\n  ')}'")
    print(f"Test 4: '{trim_string('no trailing')}'")
    print(f"Test 5: '{trim_string('   \\\\n\\\\n')}'")
