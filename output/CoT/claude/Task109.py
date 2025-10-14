
import re

def validate_email(email):
    """Validates email format"""
    if not email or len(email) > 254:
        return False
    # RFC 5322 compliant email pattern with length limits
    email_pattern = r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$'
    return bool(re.match(email_pattern, email))

def validate_phone_number(phone):
    """Validates phone number (US format)"""
    if not phone:
        return False
    # US phone format: (123) 456-7890 or 123-456-7890 or 1234567890
    phone_pattern = r'^(\\+?1)?[\\s-]?\\(?[0-9]{3}\\)?[\\s-]?[0-9]{3}[\\s-]?[0-9]{4}$'
    return bool(re.match(phone_pattern, phone))

def validate_url(url):
    """Validates URL format"""
    if not url or len(url) > 2048:
        return False
    url_pattern = r'^(https?://)(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)$'
    return bool(re.match(url_pattern, url))

def validate_password(password):
    """Validates strong password"""
    if not password or len(password) < 8 or len(password) > 128:
        return False
    # Password must contain uppercase, lowercase, digit, and special character
    password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$'
    return bool(re.match(password_pattern, password))

def validate_username(username):
    """Validates username (alphanumeric and underscore, 3-20 characters)"""
    if not username:
        return False
    username_pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return bool(re.match(username_pattern, username))

if __name__ == "__main__":
    print("=== User Input Validation Tests ===\\n")
    
    # Test Case 1: Valid inputs
    print("Test Case 1: Valid Inputs")
    print(f"Email 'user@example.com': {validate_email('user@example.com')}")
    print(f"Phone '123-456-7890': {validate_phone_number('123-456-7890')}")
    print(f"URL 'https://www.example.com': {validate_url('https://www.example.com')}")
    print(f"Password 'SecurePass123!': {validate_password('SecurePass123!')}")
    print(f"Username 'john_doe123': {validate_username('john_doe123')}")
    print()
    
    # Test Case 2: Invalid email
    print("Test Case 2: Invalid Email")
    print(f"Email 'invalid.email': {validate_email('invalid.email')}")
    print(f"Email 'user@': {validate_email('user@')}")
    print(f"Email '@example.com': {validate_email('@example.com')}")
    print()
    
    # Test Case 3: Invalid phone number
    print("Test Case 3: Invalid Phone Number")
    print(f"Phone '12345': {validate_phone_number('12345')}")
    print(f"Phone 'abc-def-ghij': {validate_phone_number('abc-def-ghij')}")
    print()
    
    # Test Case 4: Invalid password (weak)
    print("Test Case 4: Invalid Password")
    print(f"Password 'weak': {validate_password('weak')}")
    print(f"Password 'NoSpecialChar1': {validate_password('NoSpecialChar1')}")
    print(f"Password 'nouppercas1!': {validate_password('nouppercas1!')}")
    print()
    
    # Test Case 5: Invalid username
    print("Test Case 5: Invalid Username")
    print(f"Username 'ab': {validate_username('ab')}")
    print(f"Username 'user@name': {validate_username('user@name')}")
    print(f"Username 'this_is_way_too_long_username': {validate_username('this_is_way_too_long_username')}")
