def check_password_strength(password):
    """
    Checks the strength of a given password.

    :param password: The password string to check.
    :return: True if the password is strong, False otherwise.
    """
    # Handle None or empty input and check length
    if not password or len(password) < 8:
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
        "StrongPass123", # Strong
        "weak",          # Weak: too short, no upper, no digit
        "NoDigitPass",   # Weak: no digit
        "nouppercase1",  # Weak: no uppercase
        "NOLOWERCASE1"   # Weak: no lowercase
    ]
    
    print("Python Test Cases:")
    for password in test_cases:
        print(f'Password: "{password}" -> Strong: {check_password_strength(password)}')