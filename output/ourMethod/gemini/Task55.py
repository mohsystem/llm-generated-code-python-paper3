import re
from typing import Optional

# Pre-compiled regex pattern for email validation based on OWASP recommendations.
# This provides a good balance of accuracy and performance for common email formats.
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$"
)

def is_valid_email(email: Optional[str]) -> bool:
    """
    Validates an email address against a standard pattern.

    Args:
        email: The string to be validated.

    Returns:
        True if the email is valid, False otherwise.
    """
    if not isinstance(email, str):
        return False
    return EMAIL_REGEX.fullmatch(email) is not None

def main():
    """
    Runs test cases for the email validation function.
    """
    test_emails = [
        "test@example.com",        # valid
        "test.name@example.co.uk", # valid
        "test..name@example.com",  # invalid (consecutive dots)
        "test@example",            # invalid (no TLD)
        "@example.com"             # invalid (empty local part)
    ]

    for email in test_emails:
        print(f"Email: {email} is valid? {is_valid_email(email)}")

if __name__ == "__main__":
    main()