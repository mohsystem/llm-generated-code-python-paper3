
import os
import sys

def constant_time_equals(a, b):
    """Constant-time string comparison to prevent timing attacks"""
    if a is None or b is None:
        return False
    
    length_a = len(a)
    length_b = len(b)
    
    # Use the longer length to prevent timing attacks
    max_length = max(length_a, length_b)
    result = length_a ^ length_b  # Different lengths contribute to mismatch
    
    for i in range(max_length):
        char_a = ord(a[i]) if i < length_a else 0
        char_b = ord(b[i]) if i < length_b else 0
        result |= char_a ^ char_b
    
    return result == 0

def verify_password(file_path, entered_password):
    """Verify password from file against entered password"""
    stored_password = None
    
    try:
        # Read password from file securely
        with open(file_path, 'r') as file:
            stored_password = file.read().strip()
        
        # Constant-time comparison
        matches = constant_time_equals(stored_password, entered_password)
        
        return matches
        
    except FileNotFoundError:
        print(f"Error: Password file '{file_path}' not found", file=sys.stderr)
        return False
    except IOError as e:
        print(f"Error reading password file: {e}", file=sys.stderr)
        return False
    finally:
        # Clear sensitive data from memory
        if stored_password is not None:
            stored_password = None

def main():
    """Main function with test cases"""
    print("=== Password Verification Test Cases ===\\n")
    
    # Create test password file
    test_file = "test_password.txt"
    try:
        with open(test_file, 'w') as f:
            f.write("SecurePass123!")
    except IOError:
        print("Failed to create test file", file=sys.stderr)
        return
    
    # Test Case 1: Correct password
    print("Test 1 - Correct password:")
    result1 = verify_password(test_file, "SecurePass123!")
    print(f"Result: {'MATCH' if result1 else 'NO MATCH'}\\n")
    
    # Test Case 2: Incorrect password
    print("Test 2 - Incorrect password:")
    result2 = verify_password(test_file, "WrongPassword")
    print(f"Result: {'MATCH' if result2 else 'NO MATCH'}\\n")
    
    # Test Case 3: Password with different case
    print("Test 3 - Different case:")
    result3 = verify_password(test_file, "securepass123!")
    print(f"Result: {'MATCH' if result3 else 'NO MATCH'}\\n")
    
    # Test Case 4: Empty password
    print("Test 4 - Empty password:")
    result4 = verify_password(test_file, "")
    print(f"Result: {'MATCH' if result4 else 'NO MATCH'}\\n")
    
    # Test Case 5: Password with extra characters
    print("Test 5 - Password with extra characters:")
    result5 = verify_password(test_file, "SecurePass123!Extra")
    print(f"Result: {'MATCH' if result5 else 'NO MATCH'}\\n")
    
    # Cleanup test file
    try:
        os.remove(test_file)
    except OSError:
        print("Failed to delete test file", file=sys.stderr)

if __name__ == "__main__":
    main()
