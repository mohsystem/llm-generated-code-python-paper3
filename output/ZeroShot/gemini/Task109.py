import re

def validate_input(input_str: str, regex_pattern: str) -> bool:
    """
    Validates a string against a given regular expression pattern.

    Args:
        input_str: The string to validate.
        regex_pattern: The regular expression pattern.

    Returns:
        True if the input matches the pattern, False otherwise.
    """
    if not isinstance(input_str, str) or not isinstance(regex_pattern, str):
        return False
    try:
        # re.fullmatch ensures the entire string matches the pattern
        return re.fullmatch(regex_pattern, input_str) is not None
    except re.error as e:
        # Handle potential errors in the regex pattern itself
        print(f"Invalid regex pattern: {e}")
        return False


def main():
    """Main function with test cases."""
    test_cases = [
        # (input, pattern, expected_result)
        ("test@example.com", r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", True),
        ("123-456-7890", r"^\d{3}-\d{3}-\d{4}$", True),
        ("Alpha123", r"^[a-zA-Z0-9]+$", True),
        ("Alpha123!", r"^[a-zA-Z0-9]+$", False),
        ("not-an-email", r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", False)
    ]

    print("--- Python Test Cases ---")
    for i, (input_str, pattern, expected) in enumerate(test_cases, 1):
        result = validate_input(input_str, pattern)
        print(f"Test Case {i}:")
        print(f"Input: \"{input_str}\"")
        print(f"Pattern: \"{pattern}\"")
        print(f"Result: {result} | Expected: {expected}")
        print(f"Status: {'Passed' if result == expected else 'Failed'}")
        print()

if __name__ == "__main__":
    main()