
def convert_to_integer(input_str):
    try:
        return int(input_str.strip())
    except ValueError:
        print(f"Error: Invalid input. Cannot convert '{input_str}' to integer.")
        return None

def main():
    # Test cases
    test_cases = ["123", "-456", "0", "abc", "12.34"]
    
    print("Running test cases:")
    for test_case in test_cases:
        print(f"Input: '{test_case}' -> ", end="")
        result = convert_to_integer(test_case)
        if result is not None:
            print(f"Output: {result}")
    
    # Interactive input
    print("\\nEnter a value to convert to integer (or 'exit' to quit):")
    
    while True:
        try:
            user_input = input()
            if user_input.lower() == 'exit':
                break
            result = convert_to_integer(user_input)
            if result is not None:
                print(f"Successfully converted to: {result}")
            print("Enter another value (or 'exit' to quit):")
        except EOFError:
            break

if __name__ == "__main__":
    main()
