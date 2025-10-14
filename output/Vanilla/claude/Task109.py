
import re

class ValidationResult:
    def __init__(self, is_valid, message):
        self.is_valid = is_valid
        self.message = message

def validate_email(email):
    email_pattern = r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$'
    
    if re.match(email_pattern, email):
        return ValidationResult(True, "Valid email address")
    else:
        return ValidationResult(False, "Invalid email address")

def validate_phone(phone):
    phone_pattern = r'^\\+?[1-9]\\d{1,14}$|^\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}$'
    
    if re.match(phone_pattern, phone):
        return ValidationResult(True, "Valid phone number")
    else:
        return ValidationResult(False, "Invalid phone number")

def validate_password(password):
    password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$'
    
    if re.match(password_pattern, password):
        return ValidationResult(True, "Valid password")
    else:
        return ValidationResult(False, "Invalid password (must be 8+ chars with uppercase, lowercase, digit, and special character)")

def validate_username(username):
    username_pattern = r'^[a-zA-Z0-9_]{3,20}$'
    
    if re.match(username_pattern, username):
        return ValidationResult(True, "Valid username")
    else:
        return ValidationResult(False, "Invalid username (must be 3-20 alphanumeric characters or underscore)")

def validate_url(url):
    url_pattern = r'^(https?|ftp)://[^\\s/$.?#].[^\\s]*$'
    
    if re.match(url_pattern, url, re.IGNORECASE):
        return ValidationResult(True, "Valid URL")
    else:
        return ValidationResult(False, "Invalid URL")

if __name__ == "__main__":
    print("===== Test Case 1: Email Validation =====")
    result1 = validate_email("user@example.com")
    print("Input: user@example.com")
    print(f"Result: {result1.is_valid} - {result1.message}")
    print()
    
    print("===== Test Case 2: Phone Validation =====")
    result2 = validate_phone("123-456-7890")
    print("Input: 123-456-7890")
    print(f"Result: {result2.is_valid} - {result2.message}")
    print()
    
    print("===== Test Case 3: Password Validation =====")
    result3 = validate_password("SecurePass123!")
    print("Input: SecurePass123!")
    print(f"Result: {result3.is_valid} - {result3.message}")
    print()
    
    print("===== Test Case 4: Username Validation =====")
    result4 = validate_username("john_doe123")
    print("Input: john_doe123")
    print(f"Result: {result4.is_valid} - {result4.message}")
    print()
    
    print("===== Test Case 5: URL Validation =====")
    result5 = validate_url("https://www.example.com")
    print("Input: https://www.example.com")
    print(f"Result: {result5.is_valid} - {result5.message}")
