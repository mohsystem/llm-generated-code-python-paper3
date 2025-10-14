import sys

def is_password_strong(password: str) -> bool:
    """
    Checks if a password meets the strength criteria.
    Criteria:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit

    :param password: The password string to check.
    :return: True if the password is strong, False otherwise.
    """
    if not isinstance(password, str) or len(password) < 8:
        return False

    has_upper = False
    has_lower = False
    has_digit = False

    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_digit = True
        
        # Optimization: if all conditions are met, no need to check further.
        if has_upper and has_lower and has_digit:
            return True
            
    return has_upper and has_lower and has_digit

def main():
    """Main function with test cases."""
    test_passwords = [
        "StrongPwd1",      # Should be True
        "weakpwd1",        # Should be False (missing uppercase)
        "WEAKPWD1",        # Should be False (missing lowercase)
        "WeakPassword",    # Should be False (missing digit)
        "Wpwd1"            # Should be False (too short)
    ]

    for password in test_passwords:
        print(f'Password: "{password}" -> Strong: {is_password_strong(password)}')

if __name__ == "__main__":
    main()