import re

def validate_input(input_string: str, regex_pattern: str) -> bool:
    """
    Validates an input string against a given regular expression.

    Args:
        input_string: The string to validate.
        regex_pattern: The regular expression pattern.
    
    Returns:
        True if the entire input string matches the pattern, False otherwise.
    
    Note:
        It is assumed the regex_pattern is from a trusted source to prevent ReDoS attacks.
    """
    if not isinstance(input_string, str) or not isinstance(regex_pattern, str):
        return False
    try:
        # re.fullmatch ensures the entire string matches the pattern.
        return re.fullmatch(regex_pattern, input_string) is not None
    except re.error as e:
        # Handle cases where the provided regex is invalid
        print(f"Invalid regex pattern: {e}")
        return False


if __name__ == "__main__":
    # Test Case 1: Valid Email
    email_valid = "test@example.com"
    # Using raw string (r"...") is best practice for regex in Python
    email_regex = r"^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$"
    print(f"1. Testing '{email_valid}' against email regex: {'Valid' if validate_input(email_valid, email_regex) else 'Invalid'}")

    # Test Case 2: Invalid Email
    email_invalid = "test@example"
    print(f"2. Testing '{email_invalid}' against email regex: {'Valid' if validate_input(email_invalid, email_regex) else 'Invalid'}")

    # Test Case 3: Valid US Phone Number
    phone_valid = "123-456-7890"
    phone_regex = r"^\d{3}-\d{3}-\d{4}$"
    print(f"3. Testing '{phone_valid}' against phone regex: {'Valid' if validate_input(phone_valid, phone_regex) else 'Invalid'}")

    # Test Case 4: Valid Password (alphanumeric, 8+ characters)
    pass_valid = "Password123"
    pass_regex = r"^[A-Za-z0-9]{8,}$"
    print(f"4. Testing '{pass_valid}' against password regex: {'Valid' if validate_input(pass_valid, pass_regex) else 'Invalid'}")

    # Test Case 5: Invalid Password (too short)
    pass_invalid = "pass"
    print(f"5. Testing '{pass_invalid}' against password regex: {'Valid' if validate_input(pass_invalid, pass_regex) else 'Invalid'}")