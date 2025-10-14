import re

def is_valid_admin_password(password):
    """
    Checks if a given password is valid for an admin user.
    A valid admin password must:
    1. Be at least 10 characters long.
    2. Contain at least one uppercase letter.
    3. Contain at least one lowercase letter.
    4. Contain at least one digit.
    5. Contain at least one special character from the set !@#$%^&*()-_=+[]{}|;:'",.<>/?
    6. Contain the substring "admin" (case-insensitive).

    Args:
        password: The password string to validate.

    Returns:
        True if the password is valid, False otherwise.
    """
    if not isinstance(password, str) or len(password) < 10:
        return False

    # Check for required character types using regex
    has_upper = re.search(r'[A-Z]', password)
    has_lower = re.search(r'[a-z]', password)
    has_digit = re.search(r'[0-9]', password)
    # Note: Escaping special regex characters like -, [, ]
    has_special = re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:\'",.<>/?]', password)
    
    # Case-insensitive check for "admin"
    has_admin = 'admin' in password.lower()

    return all([has_upper, has_lower, has_digit, has_special, has_admin])

def main():
    test_passwords = [
        "ValidAdminPass123!",   # Should be True
        "shortAd1!",              # Should be False (too short)
        "nouppercaseadmin1!",     # Should be False (no uppercase)
        "NoSpecialAdmin123",      # Should be False (no special character)
        "NoKeyword123!@#",        # Should be False (no "admin" substring)
        "NoDigitsADMIN!@#"        # Should be False (no digits)
    ]
    
    print("Running Python Test Cases:")
    for password in test_passwords:
        print(f"Password: \"{password}\" is valid? {is_valid_admin_password(password)}")

if __name__ == "__main__":
    main()