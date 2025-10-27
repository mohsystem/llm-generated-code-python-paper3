def trim_trailing_whitespace(input_str: str) -> str:
    """
    Trims trailing whitespace from a given string.

    Args:
        input_str: The string to be trimmed.

    Returns:
        The string with trailing whitespace removed.
    """
    # The rstrip() method returns a copy of the string with trailing
    # whitespace removed. It is safe and handles various whitespace types.
    if not isinstance(input_str, str):
        return ""
    return input_str.rstrip()

def main():
    """
    Main function to demonstrate the trim_trailing_whitespace function
    with five test cases.
    """
    test_cases = [
        "hello world   ",
        "test\t \t",
        "no_trailing",
        "   \t\n ",
        "  leading and trailing  "
    ]

    print("Running Python test cases:")
    for test in test_cases:
        trimmed = trim_trailing_whitespace(test)
        print(f'Input:  "{test}"\nOutput: "{trimmed}"\n')

if __name__ == "__main__":
    main()