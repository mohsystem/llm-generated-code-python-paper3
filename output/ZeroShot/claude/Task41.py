
MAX_INPUT_LENGTH = 1024

def process_string(input_str):
    """\n    Process a string input safely with buffer overflow protection\n    """
    # Check for None
    if input_str is None:
        return "Error: Null input"
    
    # Validate input length
    if len(input_str) > MAX_INPUT_LENGTH:
        return f"Error: Input exceeds maximum length of {MAX_INPUT_LENGTH}"
    
    # Process the string (example: convert to uppercase and strip whitespace)
    processed = input_str.strip().upper()
    return f"Processed: {processed}"

def main():
    """Main function with test cases"""
    # Test case 1: Normal string
    print("Test 1:", process_string("Hello World"))
    
    # Test case 2: Empty string
    print("Test 2:", process_string(""))
    
    # Test case 3: String with whitespace
    print("Test 3:", process_string("  Python Programming  "))
    
    # Test case 4: None input
    print("Test 4:", process_string(None))
    
    # Test case 5: Very long string
    long_string = "A" * 2000
    print("Test 5:", process_string(long_string))

if __name__ == "__main__":
    main()
