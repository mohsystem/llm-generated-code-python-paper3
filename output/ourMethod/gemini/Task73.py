import string

MIN_LENGTH = 12
MAX_LENGTH = 128
SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?~"

def is_admin_password_valid(password: str) -> bool:
    """
    Checks if a given password is valid for an admin user based on a strong password policy.
    Policy:
    - Length between 12 and 128 characters.
    - Contains at least one uppercase letter.
    - Contains at least one lowercase letter.
    - Contains at least one digit.
    - Contains at least one special character.

    Args:
        password: The password string to validate.

    Returns:
        True if the password is valid, False otherwise.
    """
    if not isinstance(password, str) or not (MIN_LENGTH <= len(password) <= MAX_LENGTH):
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in SPECIAL_CHARACTERS for c in password)

    return has_upper and has_lower and has_digit and has_special

if __name__ == '__main__':
    test_passwords = [
        "Admin@1234567",       # Valid
        "admin@1234567",       # Invalid: no uppercase
        "Admin1234567",        # Invalid: no special character
        "Admin@",              # Invalid: too short
        "ADMIN@1234567"        # Invalid: no lowercase
    ]

    for password in test_passwords:
        print(f'Password: "{password}" is valid: {is_admin_password_valid(password)}')