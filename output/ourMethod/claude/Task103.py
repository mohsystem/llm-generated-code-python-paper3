
from typing import Optional

def check_password_strength(password: Optional[str]) -> bool:
    """\n    Validates password strength based on specific criteria.\n    \n    Args:\n        password: The password string to validate\n        \n    Returns:\n        True if password meets all criteria, False otherwise\n    """
    # Validate input is not None
    if password is None:
        return False
    
    # Validate input is a string
    if not isinstance(password, str):
        return False
    
    # Check minimum length requirement (at least 8 characters)
    if len(password) < 8:
        return False
    
    # Check maximum length to prevent resource exhaustion
    if len(password) > 128:
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
        
        # Early exit if all criteria are met
        if has_uppercase and has_lowercase and has_digit:
            return True
    
    # Return True only if all three criteria are met
    return has_uppercase and has_lowercase and has_digit


def main() -> None:
    """Main function with test cases."""
    # Test cases
    test_passwords = [
        "Abcdefg1",       # Valid: 8 chars, upper, lower, digit
        "Short1Aa",       # Valid: 8 chars, all criteria met
        "alllowercase1",  # Invalid: no uppercase
        "ALLUPPERCASE1",  # Invalid: no lowercase
        "NoDigitsHere"    # Invalid: no digit
    ]
    
    print("Password Strength Checker")
    print("=========================")
    
    for password in test_passwords:
        is_strong = check_password_strength(password)
        print(f'Password: "{password}" - {"STRONG" if is_strong else "WEAK"}')
    
    # Additional test with None
    print(f'Password: None - {"STRONG" if check_password_strength(None) else "WEAK"}')


if __name__ == "__main__":
    main()
