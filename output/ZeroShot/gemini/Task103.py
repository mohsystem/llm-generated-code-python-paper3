def check_password_strength(password):
    """
    Checks the strength of a given password.
    A strong password must be at least 8 characters long, contain both
    uppercase and lowercase letters, and at least one digit.
    
    :param password: The password string to validate.
    :return: True if the password is strong, False otherwise.
    """
    if len(password) < 8:
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
    
    return has_upper and has_lower and has_digit

if __name__ == "__main__":
    test_cases = [
        "Password123",    # Strong
        "password123",    # Weak (no uppercase)
        "PASSWORD123",    # Weak (no lowercase)
        "Password",       # Weak (no digit)
        "pass"            # Weak (too short)
    ]

    print("--- Python Test Cases ---")
    for password in test_cases:
        is_strong = check_password_strength(password)
        print(f'Password: "{password}" -> Strong: {is_strong}')