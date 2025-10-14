import re

MIN_PASSWORD_LENGTH = 12
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "12345", "12345678", 
    "111111", "1234567", "password123"
}

def is_admin_password_valid(password: str) -> bool:
    """
    Checks if a given password is valid for an admin user based on security policies.

    Args:
        password: The password string to validate.

    Returns:
        True if the password is valid, False otherwise.
    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False

    # Check for character diversity using regular expressions
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password):
        return False

    # Check against a list of common passwords
    if password in COMMON_PASSWORDS:
        return False

    # Check if the password contains "admin" (case-insensitive)
    if "admin" in password.lower():
        return False

    return True

# Main function with test cases
def main():
    test_passwords = [
        "ValidP@ssw0rd!2024",  # Valid
        "Sh0rt!P@s",           # Invalid: Too short
        "NoDigitPassword!",    # Invalid: Missing digit
        "password123",         # Invalid: Common password
        "MyAdm1nPassword!"     # Invalid: Contains "admin"
    ]
    
    print("Running Python Test Cases:")
    for pwd in test_passwords:
        print(f"Password: \"{pwd}\" -> Is Valid: {is_admin_password_valid(pwd)}")

if __name__ == "__main__":
    main()