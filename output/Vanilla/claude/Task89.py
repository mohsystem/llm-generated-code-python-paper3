
def compare_passwords(stored_password, entered_password):
    if stored_password is None or entered_password is None:
        return False
    
    if len(stored_password) != len(entered_password):
        return False
    
    for i in range(len(stored_password)):
        if stored_password[i] != entered_password[i]:
            return False
    
    return True

def read_password_from_file(filename):
    try:
        with open(filename, 'r') as file:
            password = file.readline().strip()
            return password
    except IOError:
        return None

def verify_password(filename, entered_password):
    stored_password = read_password_from_file(filename)
    return compare_passwords(stored_password, entered_password)

if __name__ == "__main__":
    # Create test file with password
    try:
        with open("password.txt", 'w') as file:
            file.write("SecurePass123")
    except IOError:
        print("Error creating test file")
    
    # Test Case 1: Correct password
    print("Test 1 - Correct password:")
    result1 = verify_password("password.txt", "SecurePass123")
    print(f"Result: {result1} (Expected: True)\\n")
    
    # Test Case 2: Incorrect password
    print("Test 2 - Incorrect password:")
    result2 = verify_password("password.txt", "WrongPass123")
    print(f"Result: {result2} (Expected: False)\\n")
    
    # Test Case 3: Password with different length
    print("Test 3 - Different length:")
    result3 = verify_password("password.txt", "Short")
    print(f"Result: {result3} (Expected: False)\\n")
    
    # Test Case 4: Empty password
    print("Test 4 - Empty password:")
    result4 = verify_password("password.txt", "")
    print(f"Result: {result4} (Expected: False)\\n")
    
    # Test Case 5: Case sensitive check
    print("Test 5 - Case sensitive:")
    result5 = verify_password("password.txt", "securepass123")
    print(f"Result: {result5} (Expected: False)\\n")
