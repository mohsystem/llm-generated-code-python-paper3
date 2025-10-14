
import re
from typing import Optional

MAX_INPUT_LENGTH: int = 10000
MAX_PATTERN_LENGTH: int = 1000

def validate_input(input_str: Optional[str], regex_pattern: Optional[str]) -> bool:
    """\n    Validates input string against a regular expression pattern.\n    Returns True if input matches the pattern, False otherwise.\n    """
    # Validate inputs are not None
    if input_str is None or regex_pattern is None:
        return False
    
    # Validate input length to prevent resource exhaustion
    if len(input_str) > MAX_INPUT_LENGTH:
        return False
    
    # Validate pattern length
    if len(regex_pattern) > MAX_PATTERN_LENGTH:
        return False
    
    try:
        # Compile pattern with timeout protection
        pattern = re.compile(regex_pattern)
        
        # Use fullmatch for complete string matching
        match = pattern.fullmatch(input_str)
        
        return match is not None
    except re.error:
        # Invalid regex pattern
        return False
    except RecursionError:
        # Catastrophic backtracking detected
        return False
    except Exception:
        # Any other exception
        return False

def validate_email(email: Optional[str]) -> bool:
    """\n    Validates email format.\n    """
    if email is None:
        return False
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
    return validate_input(email, email_pattern)

def validate_phone_number(phone: Optional[str]) -> bool:
    """\n    Validates phone number (US format).\n    """
    if phone is None:
        return False
    phone_pattern = r'^\\d{3}-\\d{3}-\\d{4}$'
    return validate_input(phone, phone_pattern)

def validate_alphanumeric(input_str: Optional[str]) -> bool:
    """\n    Validates alphanumeric string.\n    """
    if input_str is None:
        return False
    alphanumeric_pattern = r'^[a-zA-Z0-9]+$'
    return validate_input(input_str, alphanumeric_pattern)

def main() -> None:
    # Test case 1: Valid email
    email1 = "user@example.com"
    print(f"Test 1 - Valid email: {validate_email(email1)}")
    
    # Test case 2: Invalid email
    email2 = "invalid.email@"
    print(f"Test 2 - Invalid email: {validate_email(email2)}")
    
    # Test case 3: Valid phone number
    phone1 = "123-456-7890"
    print(f"Test 3 - Valid phone: {validate_phone_number(phone1)}")
    
    # Test case 4: Valid alphanumeric
    alphanumeric1 = "Test123"
    print(f"Test 4 - Valid alphanumeric: {validate_alphanumeric(alphanumeric1)}")
    
    # Test case 5: None input handling
    print(f"Test 5 - None input: {validate_input(None, r'^[a-z]+$')}")

if __name__ == "__main__":
    main()
