
def is_valid_admin_password(password):
    """\n    Validates if a given password meets admin security requirements.\n    \n    Args:\n        password (str): The password to validate\n        \n    Returns:\n        bool: True if password is valid, False otherwise\n    """
    MIN_PASSWORD_LENGTH = 12
    COMMON_PASSWORDS = {
        "password123!", "admin@123456", "welcome@2024", 
        "p@ssw0rd1234", "administrator1!"
    }
    
    # Check for None or empty string
    if password is None or not password:
        return False
    
    # Check minimum length
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    
    # Check for common passwords (case-insensitive)
    if password.lower() in COMMON_PASSWORDS:
        return False
    
    # Check for required character types
    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False
    
    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_digit = True
        elif not char.isspace():
            has_special = True
    
    return has_upper and has_lower and has_digit and has_special


def main():
    # Test cases
    test_passwords = [
        "SecureP@ssw0rd123",  # Valid
        "Weak1!",              # Too short
        "nosymbolsupper1",     # No uppercase or special
        "NOLOWERCASE123!",     # No lowercase
        "Admin@123456"         # Common password
    ]
    
    print("Admin Password Validation Results:")
    for i, password in enumerate(test_passwords, 1):
        result = is_valid_admin_password(password)
        status = "VALID" if result else "INVALID"
        print(f'Test {i}: "{password}" -> {status}')


if __name__ == "__main__":
    main()
