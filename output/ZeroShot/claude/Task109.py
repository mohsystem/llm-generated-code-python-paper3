
import re

def validate_email(email):
    """Validate email address"""
    if not email:
        return False
    email_regex = r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$'
    return bool(re.match(email_regex, email))

def validate_phone(phone):
    """Validate phone number (US format)"""
    if not phone:
        return False
    phone_regex = r'^(\\+1)?[-.\\\\s]?\\(?([0-9]{3})\\)?[-.\\\\s]?([0-9]{3})[-.\\\\s]?([0-9]{4})$'
    return bool(re.match(phone_regex, phone))

def validate_password(password):
    """Validate password (min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special char)"""
    if not password:
        return False
    password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$'
    return bool(re.match(password_regex, password))

def validate_url(url):
    """Validate URL"""
    if not url:
        return False
    url_regex = r'^(https?|ftp)://[^\\s/$.?#].[^\\s]*$'
    return bool(re.match(url_regex, url, re.IGNORECASE))

def validate_username(username):
    """Validate username (alphanumeric and underscore, 3-16 chars)"""
    if not username:
        return False
    username_regex = r'^[a-zA-Z0-9_]{3,16}$'
    return bool(re.match(username_regex, username))

if __name__ == "__main__":
    print("=== Test Case 1: Email Validation ===")
    email1 = "user@example.com"
    email2 = "invalid.email@"
    print(f"{email1} is valid: {validate_email(email1)}")
    print(f"{email2} is valid: {validate_email(email2)}")
    
    print("\\n=== Test Case 2: Phone Validation ===")
    phone1 = "(123) 456-7890"
    phone2 = "123-456-7890"
    print(f"{phone1} is valid: {validate_phone(phone1)}")
    print(f"{phone2} is valid: {validate_phone(phone2)}")
    
    print("\\n=== Test Case 3: Password Validation ===")
    pwd1 = "SecurePass123!"
    pwd2 = "weak"
    print(f"{pwd1} is valid: {validate_password(pwd1)}")
    print(f"{pwd2} is valid: {validate_password(pwd2)}")
    
    print("\\n=== Test Case 4: URL Validation ===")
    url1 = "https://www.example.com"
    url2 = "not a url"
    print(f"{url1} is valid: {validate_url(url1)}")
    print(f"{url2} is valid: {validate_url(url2)}")
    
    print("\\n=== Test Case 5: Username Validation ===")
    user1 = "john_doe123"
    user2 = "ab"
    print(f"{user1} is valid: {validate_username(user1)}")
    print(f"{user2} is valid: {validate_username(user2)}")
