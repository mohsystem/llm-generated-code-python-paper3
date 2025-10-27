
import sys

def process_string(args):
    # Check if exactly one argument is provided
    if len(args) != 1:
        return "Error: Exactly one argument required"
    
    # Check if the argument is a string
    if not isinstance(args[0], str):
        return "Error: Argument must be a string"
    
    input_str = args[0]
    
    if not input_str:
        return ""
    
    # Trim trailing whitespace
    end = len(input_str) - 1
    while end >= 0 and input_str[end].isspace():
        end -= 1
    
    # Trim newlines
    while end >= 0 and input_str[end] in ('\\n', '\\r'):
        end -= 1
    
    # Return the trimmed string (strings are immutable in Python)
    return input_str[:end + 1] if end >= 0 else ""

def main():
    # Test case 1: Normal string with trailing spaces
    test1 = ["Hello World   "]
    print(f"Test 1: '{process_string(test1)}'")
    
    # Test case 2: String with trailing newlines
    test2 = ["Hello\\n\\n"]
    print(f"Test 2: '{process_string(test2)}'")
    
    # Test case 3: String with both spaces and newlines
    test3 = ["Test String  \\n  \\n"]
    print(f"Test 3: '{process_string(test3)}'")
    
    # Test case 4: Empty string
    test4 = [""]
    print(f"Test 4: '{process_string(test4)}'")
    
    # Test case 5: No trailing whitespace
    test5 = ["Clean"]
    print(f"Test 5: '{process_string(test5)}'")

if __name__ == "__main__":
    main()
