def reverse_string(s):
    """
    Reverses a given string.

    Args:
        s: The string to be reversed.

    Returns:
        The reversed string, or None if the input is None.
    """
    # Check for None input to avoid TypeError
    if s is None:
        return None
    # Python's slicing is a concise and efficient way to reverse a string
    return s[::-1]

if __name__ == "__main__":
    # 5 test cases
    test_cases = [
        "hello world",
        "12345",
        "a",
        "",
        "Palindrome"
    ]

    for test in test_cases:
        reversed_str = reverse_string(test)
        print(f'Original: "{test}", Reversed: "{reversed_str}"')