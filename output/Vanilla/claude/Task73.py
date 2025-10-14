
def is_valid_password(password):
    if password is None or len(password) < 8:
        return False
    
    has_upper_case = False
    has_lower_case = False
    has_digit = False
    has_special_char = False
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    for c in password:
        if c.isupper():
            has_upper_case = True
        elif c.islower():
            has_lower_case = True
        elif c.isdigit():
            has_digit = True
        elif c in special_chars:
            has_special_char = True
    
    return has_upper_case and has_lower_case and has_digit and has_special_char


if __name__ == "__main__":
    # Test cases
    print("Test 1: 'Admin@123' ->", is_valid_password("Admin@123"))
    print("Test 2: 'password' ->", is_valid_password("password"))
    print("Test 3: 'Pass123' ->", is_valid_password("Pass123"))
    print("Test 4: 'ADMIN@123' ->", is_valid_password("ADMIN@123"))
    print("Test 5: 'Secure#Pass2024' ->", is_valid_password("Secure#Pass2024"))
