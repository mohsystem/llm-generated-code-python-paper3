from typing import Optional

def reverse_string(s: Optional[str]) -> Optional[str]:
    """
    Reverses a given string.

    Args:
        s: The string to be reversed.

    Returns:
        The reversed string, or None if the input is None.
    """
    if s is None:
        return None
    # String slicing [::-1] is a concise and efficient way to reverse a string in Python.
    # It correctly handles Unicode characters.
    return s[::-1]

def main():
    """Main function with test cases."""
    test_cases = [
        "Hello, World!",
        "madam",
        "12345",
        "",
        "a"
    ]

    for test_case in test_cases:
        print(f'Original: "{test_case}"')
        reversed_str = reverse_string(test_case)
        print(f'Reversed: "{reversed_str}"')
        print()

if __name__ == "__main__":
    main()