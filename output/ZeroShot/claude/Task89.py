
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
            return file.readline().strip()
    except IOError as e:
        print(f"Error reading password file: {e}")
        return None

def verify_password(filename, entered_password):
    stored_password = read_password_from_file(filename)
    return compare_passwords(stored_password, entered_password)

if __name__ == "__main__":
    # Create a test password file
    test_file = "password.txt"
    try:
        with open(test_file, 'w') as file:
            file.write("SecurePass123\\n")
    except IOError as e:
        print(f"Error creating test file: {e}")
    
    # Test cases
    print("Test Case 1 - Correct password:")
    result1 = verify_password(test_file, "SecurePass123")
    print(f"Result: {'Access Granted' if result1 else 'Access Denied'}")
    
    print("\\nTest Case 2 - Incorrect password:")
    result2 = verify_password(test_file, "WrongPass456")
    print(f"Result: {'Access Granted' if result2 else 'Access Denied'}")
    
    print("\\nTest Case 3 - Empty password:")
    result3 = verify_password(test_file, "")
    print(f"Result: {'Access Granted' if result3 else 'Access Denied'}")
    
    print("\\nTest Case 4 - Case sensitive check:")
    result4 = verify_password(test_file, "securepass123")
    print(f"Result: {'Access Granted' if result4 else 'Access Denied'}")
    
    print("\\nTest Case 5 - Partial match:")
    result5 = verify_password(test_file, "SecurePass")
    print(f"Result: {'Access Granted' if result5 else 'Access Denied'}")
    
    # Clean up test file
    import os
    try:
        os.remove(test_file)
    except:
        pass
