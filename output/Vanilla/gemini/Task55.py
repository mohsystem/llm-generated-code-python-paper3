import re

def is_valid_email(email):
    """
    Validates an email address using a regular expression.

    :param email: The email string to validate.
    :return: True if the email is valid, False otherwise.
    """
    if not isinstance(email, str):
        return False
    # A common regex for email validation.
    email_regex = r'^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$'
    return re.fullmatch(email_regex, email) is not None

def main():
    """
    Main function with test cases.
    """
    test_emails = [
        "test.user@example.com",      # Valid
        "user@sub.domain.co.uk",  # Valid
        "invalid-email",              # Invalid (no @)
        "user@.com",                  # Invalid (domain starts with a dot)
        "user@domain..com"            # Invalid (consecutive dots in domain)
    ]

    print("--- Python Email Validation ---")
    for email in test_emails:
        print(f"Email: {email} -> Is Valid: {is_valid_email(email)}")

if __name__ == "__main__":
    main()