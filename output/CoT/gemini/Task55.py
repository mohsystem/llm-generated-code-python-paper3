import re

def is_valid_email(email):
    """
    Validates an email address using a regular expression.

    :param email: The string to validate.
    :return: True if the email is valid, False otherwise.
    """
    # A non-string or empty string is not a valid email
    if not isinstance(email, str) or not email:
        return False

    # Regex for standard email validation.
    # The 'r' prefix indicates a raw string, which is good practice for regex patterns.
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    # re.fullmatch ensures the entire string matches the pattern
    return bool(re.fullmatch(email_regex, email))

def main():
    """Main function to run test cases."""
    test_emails = [
        "test@example.com",          # Valid
        "test.name+alias@example.co.uk", # Valid
        "plainaddress",              # Invalid
        "@missing-local-part.com",   # Invalid
        "test@domain@domain.com"     # Invalid
    ]

    print("Python Email Validation:")
    for email in test_emails:
        print(f"'{email}' is valid: {is_valid_email(email)}")

if __name__ == "__main__":
    main()