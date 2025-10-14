
def convert_to_integer(input_str):
    try:
        return int(input_str.strip())
    except ValueError:
        return None

if __name__ == "__main__":
    # Test cases
    test_cases = ["123", "-456", "0", "abc", "12.34"]
    
    print("Running test cases:")
    for test_case in test_cases:
        result = convert_to_integer(test_case)
        if result is not None:
            print(f"Input: '{test_case}' -> Output: {result}")
        else:
            print(f"Input: '{test_case}' -> Output: Invalid (cannot convert to integer)")
    
    # Interactive console input
    print("\\nEnter a value to convert to integer:")
    user_input = input()
    result = convert_to_integer(user_input)
    
    if result is not None:
        print(f"Successfully converted to integer: {result}")
    else:
        print(f"Error: Cannot convert '{user_input}' to integer")
