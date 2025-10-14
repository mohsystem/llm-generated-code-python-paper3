def reverse_string(s: str) -> str:
    """
    Reverses a given string.
    This function is secure as it uses Python's built-in string slicing,
    which is memory-safe and handles various string contents correctly.
    It does not modify the original string.

    Args:
        s: The string to be reversed.

    Returns:
        The reversed string.
    """
    if not isinstance(s, str):
        raise TypeError("Input must be a string")
    # String slicing [::-1] is a concise, efficient, and safe way to reverse a string.
    return s[::-1]

def main():
    """ Main function to run test cases. """
    test_cases = [
        "hello",
        "Python",
        "12345",
        "",
        "a single char"
    ]

    print("--- Python String Reversal ---")
    for test in test_cases:
        try:
            reversed_str = reverse_string(test)
            print(f"Original: \"{test}\", Reversed: \"{reversed_str}\"")
        except TypeError as e:
            print(f"Error processing input '{test}': {e}")

if __name__ == "__main__":
    main()