
import re
from typing import Optional

MAX_EMAIL_LENGTH = 320  # RFC 5321
MAX_LOCAL_PART = 64
MAX_DOMAIN_PART = 255

# Simplified email pattern that avoids catastrophic backtracking
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$')


def is_valid_email(email: Optional[str]) -> bool:
    """\n    Validates email address according to simplified RFC criteria.\n    \n    Args:\n        email: The email string to validate\n        \n    Returns:\n        True if valid, False otherwise\n    """
    # Validate input is not None
    if email is None:
        return False
    
    # Validate type
    if not isinstance(email, str):
        return False
    
    # Validate length constraints
    if len(email) == 0 or len(email) > MAX_EMAIL_LENGTH:
        return False
    
    # Validate UTF-8 encoding
    try:
        email_bytes = email.encode('utf-8')
        decoded = email_bytes.decode('utf-8')
        if email != decoded:
            return False
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False
    
    # Check for whitespace
    if email != email.strip():
        return False
    
    # Must contain exactly one @ symbol
    at_count = email.count('@')
    if at_count != 1:
        return False
    
    # Split and validate parts
    at_index = email.index('@')
    local_part = email[:at_index]
    domain_part = email[at_index + 1:]
    
    # Validate local part
    if len(local_part) == 0 or len(local_part) > MAX_LOCAL_PART:
        return False
    if local_part.startswith('.') or local_part.endswith('.'):
        return False
    if '..' in local_part:
        return False
    
    # Validate domain part
    if len(domain_part) == 0 or len(domain_part) > MAX_DOMAIN_PART:
        return False
    if domain_part.startswith('.') or domain_part.endswith('.'):
        return False
    if domain_part.startswith('-') or domain_part.endswith('-'):
        return False
    if '..' in domain_part or '--' in domain_part:
        return False
    
    # Must have at least one dot in domain
    if '.' not in domain_part:
        return False
    
    # Apply regex pattern
    if not EMAIL_PATTERN.match(email):
        return False
    
    return True


def main() -> None:
    test_cases = [
        "user@example.com",
        "test.user+tag@sub.example.co.uk",
        "invalid.email@",
        "@invalid.com",
        "no-at-sign.com"
    ]
    
    for test_case in test_cases:
        result = is_valid_email(test_case)
        print(f"Email: '{test_case}' - Valid: {result}")


if __name__ == "__main__":
    main()
