def convert_and_print(input_str):
    """
    Attempts to convert a string to an integer and prints the result or an error message.
    Args:
        input_str: The string to be converted.
    """
    if not isinstance(input_str, str) or not input_str:
        print(f"Error: Invalid input. Input is not a non-empty string.")
        return
        
    try:
        number = int(input_str)
        print(f"Successfully converted to integer: {number}")
    except ValueError:
        print(f"Error: Cannot convert '{input_str}' to an integer.")

def main():
    # Note: Python's int has arbitrary precision, so "2147483648" is a valid int.
    # The error handling for non-numeric strings is still demonstrated.
    test_cases = ["123", "-456", "abc", "2147483648", "123a"]
    
    print("--- Running Python Test Cases ---")
    for test in test_cases:
        print(f'Input: "{test}" -> ', end="")
        convert_and_print(test)
    print("--- End of Test Cases ---\n")

if __name__ == "__main__":
    main()