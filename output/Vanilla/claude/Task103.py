
def check_password_strength(password):
    if password is None:
        return "Weak"
    
    has_min_length = len(password) >= 8
    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if has_min_length and has_uppercase and has_lowercase and has_digit:
        return "Strong"
    else:
        return "Weak"


if __name__ == "__main__":
    # Test case 1: Strong password
    print("Test 1 - 'Password123':", check_password_strength("Password123"))
    
    # Test case 2: Too short
    print("Test 2 - 'Pass1':", check_password_strength("Pass1"))
    
    # Test case 3: No uppercase
    print("Test 3 - 'password123':", check_password_strength("password123"))
    
    # Test case 4: No digit
    print("Test 4 - 'PasswordTest':", check_password_strength("PasswordTest"))
    
    # Test case 5: Strong password with special characters
    print("Test 5 - 'SecurePass99!':", check_password_strength("SecurePass99!"))
