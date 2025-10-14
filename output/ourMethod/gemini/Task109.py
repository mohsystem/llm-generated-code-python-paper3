import re

def validate_input(input_string: str, regex_pattern: str) -> bool:
    """
    Validates a string against a given regular expression pattern.

    Args:
        input_string: The string to validate.
        regex_pattern: The regular expression pattern.

    Returns:
        True if the input matches the pattern, False otherwise.
    """
    if not isinstance(input_string, str) or not isinstance(regex_pattern, str):
        return False
    try:
        # re.fullmatch ensures the entire string matches the pattern
        return re.fullmatch(regex_pattern, input_string) is not None
    except re.error as e:
        # Log the exception in a real application
        print(f"Invalid regex pattern: {e}")
        return False

def main():
    """Main function with test cases."""
    # Test cases
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$"
    phone_regex = r"^\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$"
    username_regex = r"^[a-zA-Z0-9]{5,15}$"

    # Test Case 1: Valid Email
    valid_email = "test.user@example.com"
    is_email_valid = validate_input(valid_email, email_regex)
    print(f"1. Is '{valid_email}' a valid email? {is_email_valid}")

    # Test Case 2: Invalid Email
    invalid_email = "invalid-email@.com"
    is_email_invalid = validate_input(invalid_email, email_regex)
    print(f"2. Is '{invalid_email}' a valid email? {is_email_invalid}")

    # Test Case 3: Valid US Phone Number
    valid_phone = "(123) 456-7890"
    is_phone_valid = validate_input(valid_phone, phone_regex)
    print(f"3. Is '{valid_phone}' a valid US phone number? {is_phone_valid}")

    # Test Case 4: Valid Alphanumeric Username
    valid_username = "user123"
    is_username_valid = validate_input(valid_username, username_regex)
    print(f"4. Is '{valid_username}' a valid username? {is_username_valid}")

    # Test Case 5: Invalid Username (too short)
    invalid_username = "u1"
    is_username_invalid = validate_input(invalid_username, username_regex)
    print(f"5. Is '{invalid_username}' a valid username? {is_username_invalid}")

if __name__ == "__main__":
    main()