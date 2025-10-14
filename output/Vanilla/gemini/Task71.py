import sys

def convert_string_to_int(s):
    """
    Attempts to convert a string to an integer and prints the result or an error message.
    :param s: The string to be converted.
    """
    try:
        number = int(s)
        print(f'Input: "{s}" -> Converted to integer: {number}')
    except ValueError:
        print(f'Input: "{s}" -> Error: Cannot convert to integer. Invalid literal for int().')

def main():
    # Handling command-line arguments if provided
    # sys.argv[0] is the script name, arguments start at index 1
    if len(sys.argv) > 1:
        print("--- Processing Command-Line Arguments ---")
        for arg in sys.argv[1:]:
            convert_string_to_int(arg)
        print("---------------------------------------")

    # 5 hardcoded test cases
    print("\n--- Hardcoded Test Cases ---")
    test_cases = ["123", "-456", "abc", "999999999999999999999", "789xyz"]
    for test in test_cases:
        convert_string_to_int(test)
    print("--------------------------")

if __name__ == "__main__":
    main()