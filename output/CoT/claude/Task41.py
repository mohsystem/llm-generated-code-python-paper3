
def process_string(input_str):
    MAX_LENGTH = 1024
    
    if input_str is None:
        return "Error: None input"
    
    if not isinstance(input_str, str):
        return "Error: Input must be a string"
    
    if len(input_str) > MAX_LENGTH:
        return f"Error: Input exceeds maximum length of {MAX_LENGTH}"
    
    # Safe string processing - Python strings are immutable and safe
    processed = f"Processed: {input_str.strip()} (Length: {len(input_str)})"
    
    return processed


def main():
    # Test case 1: Normal input
    print("Test 1:", process_string("Hello World"))
    
    # Test case 2: Empty string
    print("Test 2:", process_string(""))
    
    # Test case 3: String with whitespace
    print("Test 3:", process_string("  Test String  "))
    
    # Test case 4: None input
    print("Test 4:", process_string(None))
    
    # Test case 5: Long string
    long_string = "A" * 500
    print("Test 5:", process_string(long_string))
    
    # Interactive mode
    print("\\nEnter a string to process (or 'exit' to quit):")
    while True:
        try:
            user_input = input()
            if user_input == "exit":
                break
            print(process_string(user_input))
            print("Enter another string (or 'exit' to quit):")
        except EOFError:
            break


if __name__ == "__main__":
    main()
