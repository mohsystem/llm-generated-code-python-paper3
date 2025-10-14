def check_password_strength(password):
    if len(password) < 8:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    return has_upper and has_lower and has_digit

def main():
    test_passwords = [
        "StrongPassword123",
        "weak",
        "NoDigitsHere",
        "nouppercase123",
        "NOLOWERCASE123"
    ]

    for password in test_passwords:
        is_strong = check_password_strength(password)
        result = "Strong" if is_strong else "Weak"
        print(f'Password: "{password}" -> {result}')

if __name__ == "__main__":
    main()