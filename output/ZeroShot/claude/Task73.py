
import re

def is_valid_admin_password(password):
    if password is None or len(password) < 12:
        return False
    
    # Check for at least one uppercase letter
    has_uppercase = any(c.isupper() for c in password)
    # Check for at least one lowercase letter
    has_lowercase = any(c.islower() for c in password)
    # Check for at least one digit
    has_digit = any(c.isdigit() for c in password)
    # Check for at least one special character
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    has_special = any(c in special_chars for c in password)
    
    # Check for common weak passwords
    lower_password = password.lower()
    weak_passwords = ["password", "admin", "123456", "qwerty", "letmein"]
    for weak in weak_passwords:
        if weak in lower_password:
            return False
    
    return has_uppercase and has_lowercase and has_digit and has_special


if __name__ == "__main__":
    # Test cases
    test_passwords = [
        "Admin@123456",           # Valid
        "SecureP@ssw0rd!",       # Valid
        "weak",                   # Invalid - too short
        "NoSpecialChar123",       # Invalid - no special character
        "Admin@Password2024"      # Valid
    ]
    
    print("Admin Password Validation Results:")
    print("=====================================")
    for password in test_passwords:
        is_valid = is_valid_admin_password(password)
        print(f"Password: {password} -> {'VALID' if is_valid else 'INVALID'}")
