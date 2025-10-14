
def convert_to_integer(input_str):
    if input_str is None or not input_str.strip():
        return None
    
    try:
        return int(input_str.strip())
    except (ValueError, OverflowError):
        return None


def main():
    # Test cases
    test_cases = ["123", "-456", "0", "abc", "999999999999999999999"]
    
    print("Running test cases:")
    for test_case in test_cases:
        result = convert_to_integer(test_case)
        if result is not None:
            print(f"Input: '{test_case}' -> Output: {result}")
        else:
            print(f"Input: '{test_case}' -> Invalid input")
    
    # Interactive mode
    print("\\n--- Interactive Mode ---")
    try:
        user_input = input("Enter a value to convert to integer: ")
        result = convert_to_integer(user_input)
        
        if result is not None:
            print(f"Successfully converted to integer: {result}")
        else:
            print("Error: Invalid input. Please enter a valid integer.")
    except EOFError:
        print("No input received.")
    except KeyboardInterrupt:
        print("\\nOperation cancelled by user.")


if __name__ == "__main__":
    main()
