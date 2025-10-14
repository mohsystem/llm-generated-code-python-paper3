import re

def is_valid_admin_password(password):
    """
    Checks if a given password is valid for an admin user.
    A valid admin password must:
    1. Be at least 12 characters long.
    2. Contain at least one uppercase letter.
    3. Contain at least one lowercase letter.
    4. Contain at least one digit.
    5. Contain at least one special character from the set: !@#$%^&*()-_=+[]{}|;:'",.<>/?
    
    Args:
        password: The password string to validate.
    
    Returns:
        True if the password is valid, False otherwise.
    """
    # 1. Rule: Check for None and minimum length
    if password is None or len(password) < 12:
        return False

    # 2. Rule: Check for at least one lowercase letter
    if not re.search(r"[a-z]", password):
        return False

    # 3. Rule: Check for at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return False

    # 4. Rule: Check for at least one digit
    if not re.search(r"\d", password):
        return False

    # 5. Rule: Check for at least one special character
    # The regex pattern [!@#$%^&*()\-=_+\[\]{}|;:'",.<>/?] is escaped for special regex characters
    if not re.search(r"[!@#$%^&*()\-=_+\[\]{}|;:'\",.<>/?]", password):
        return False

    # If all checks pass
    return True

if __name__ == '__main__':
    test_passwords = [
        "AdminP@ssw0rd123",  # Valid
        "short",              # Invalid: too short
        "NoDigitPassword!",   # Invalid: no digit
        "nouppercase@123",    # Invalid: no uppercase
        "NoSpecialChar123",   # Invalid: no special character
    ]

    print("Running Python Test Cases:")
    for password in test_passwords:
        print(f'Password: "{password}" is valid: {is_valid_admin_password(password)}')