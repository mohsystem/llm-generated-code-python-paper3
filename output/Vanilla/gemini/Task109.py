import re

def validate_input(input_string, regex_pattern):
    """
    Validates an input string against a regex pattern.
    
    Args:
        input_string: The string to validate.
        regex_pattern: The regular expression pattern.
        
    Returns:
        True if the entire string matches the pattern, False otherwise.
    """
    if input_string is None or regex_pattern is None:
        return False
    # re.fullmatch ensures the entire string matches the pattern
    return re.fullmatch(regex_pattern, input_string) is not None

def main():
    # A simple regex for email validation (raw string r"..." is used)
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    test_cases = [
        "test@example.com",         # Valid
        "test.name@example.co.uk",  # Valid
        "test@.com",                # Invalid
        "test",                     # Invalid
        "test@example"              # Invalid
    ]

    print("--- Testing Email Validation ---")
    for test_case in test_cases:
        is_valid = validate_input(test_case, email_regex)
        print(f"Input: \"{test_case}\", Is Valid? {is_valid}")

if __name__ == "__main__":
    main()