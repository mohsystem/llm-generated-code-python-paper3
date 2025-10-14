import re

def is_valid_email(email):
    """
    Validates an email address.
    Uses a regex recommended by OWASP for a good balance of correctness and security.
    """
    if not isinstance(email, str) or not email:
        return False
    
    # Basic length check according to RFCs
    if len(email) > 254:
        return False

    # Regex for validating emails (OWASP recommendation)
    email_regex = r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$"
    
    # Use re.fullmatch to ensure the whole string matches the pattern
    return re.fullmatch(email_regex, email) is not None

if __name__ == '__main__':
    test_emails = [
        "test@example.com",           # Valid
        "test.name@example.co.uk",  # Valid
        "test..name@example.com",   # Invalid (consecutive dots)
        "test@example",             # Invalid (no TLD)
        "plainaddress"              # Invalid (no '@' or domain)
    ]

    print("Python Email Validation:")
    for email in test_emails:
        print(f"'{email}' is valid: {is_valid_email(email)}")