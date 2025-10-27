
import sys

def process_string(input_str):
    """\n    Process string by trimming trailing whitespace and newlines.\n    \n    Args:\n        input_str: String to process\n        \n    Returns:\n        Processed string with trailing whitespace removed\n    """
    # Validate input is a string
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string")
    
    # Validate length to prevent excessive memory usage
    MAX_LENGTH = 1048576  # 1MB limit
    if len(input_str) > MAX_LENGTH:
        raise ValueError("Input exceeds maximum allowed length")
    
    # Convert to list for processing (strings are immutable in Python)
    chars = list(input_str)
    length = len(chars)
    
    # First loop: trim trailing whitespace
    # Iterate from end to find last non-whitespace character
    while length > 0 and chars[length - 1].isspace():
        length -= 1
    
    # Second loop: trim trailing newlines (already handled above)
    # This is redundant but follows the specification
    while length > 0 and chars[length - 1] in ('\\n', '\\r'):
        length -= 1
    
    # Return trimmed string (Python strings are null-terminated internally)
    return ''.join(chars[:length])

def main():
    # Check that exactly one argument is provided (excluding script name)
    if len(sys.argv) != 2:
        print("Error: Exactly one argument required", file=sys.stderr)
        sys.exit(1)
    
    # Get the argument (already a string in Python)
    input_str = sys.argv[1]
    
    # Check the argument is a string
    if not isinstance(input_str, str):
        print("Error: Argument must be a valid string", file=sys.stderr)
        sys.exit(1)
    
    # Process the string
    result = process_string(input_str)
    print(f"Result: '{result}'")
    
    # Test cases
    print("\\n=== Test Cases ===")
    
    # Test 1: String with trailing spaces
    test1 = "hello world   "
    print(f"Test 1 Input: '{test1}'")
    print(f"Test 1 Output: '{process_string(test1)}'")
    
    # Test 2: String with trailing newlines
    test2 = "hello world\\n\\n"
    print(f"Test 2 Input: '{repr(test2)}'")
    print(f"Test 2 Output: '{process_string(test2)}'")
    
    # Test 3: String with mixed trailing whitespace
    test3 = "hello world \\n \\t "
    print(f"Test 3 Input: '{repr(test3)}'")
    print(f"Test 3 Output: '{process_string(test3)}'")
    
    # Test 4: String with no trailing whitespace
    test4 = "hello world"
    print(f"Test 4 Input: '{test4}'")
    print(f"Test 4 Output: '{process_string(test4)}'")
    
    # Test 5: Empty string
    test5 = ""
    print(f"Test 5 Input: '{test5}'")
    print(f"Test 5 Output: '{process_string(test5)}'")

if __name__ == "__main__":
    main()
