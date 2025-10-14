
def check_password_strength(password):
    """\n    Checks if a password meets the strength criteria.\n    \n    Args:\n        password: String to validate\n        \n    Returns:\n        bool: True if password is strong, False otherwise\n    """
    # Handle None or empty password securely
    if password is None or not password:
        return False
    
    # Check minimum length
    if len(password) < 8:
        return False
    
    has_uppercase = False
    has_lowercase = False
    has_digit = False
    
    # Iterate through each character to check criteria
    for char in password:
        if char.isupper():
            has_uppercase = True
        elif char.islower():
            has_lowercase = True
        elif char.isdigit():
            has_digit = True
        
        # Early exit if all criteria met
        if has_uppercase and has_lowercase and has_digit:
            return True
    
    return has_uppercase and has_lowercase and has_digit


def main():
    """Main function with test cases."""
    # Test cases
    test_passwords = [
        "Abcd1234",      # Valid - meets all criteria
        "abcd1234",      # Invalid - no uppercase
        "ABCD1234",      # Invalid - no lowercase
        "Abcdefgh",      # Invalid - no digit
        "Abc123"         # Invalid - too short
    ]
    
    print("Password Strength Checker Results:")
    for password in test_passwords:
        is_strong = check_password_strength(password)
        result = "STRONG" if is_strong else "WEAK"
        print(f"Password: {password} -> {result}")


if __name__ == "__main__":
    main()
