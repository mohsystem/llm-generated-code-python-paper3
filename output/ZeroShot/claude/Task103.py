
def check_password_strength(password):
    if password is None:
        return "Weak: Password is None"
    
    has_min_length = len(password) >= 8
    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    if has_min_length and has_uppercase and has_lowercase and has_digit:
        return "Strong"
    else:
        weakness = "Weak: "
        if not has_min_length:
            weakness += "Less than 8 characters. "
        if not has_uppercase:
            weakness += "No uppercase letter. "
        if not has_lowercase:
            weakness += "No lowercase letter. "
        if not has_digit:
            weakness += "No digit. "
        return weakness.strip()


if __name__ == "__main__":
    # Test cases
    print("Test 1:", check_password_strength("Pass123word"))
    print("Test 2:", check_password_strength("weak"))
    print("Test 3:", check_password_strength("NoDigits"))
    print("Test 4:", check_password_strength("alllowercase123"))
    print("Test 5:", check_password_strength("ALLUPPERCASE123"))
