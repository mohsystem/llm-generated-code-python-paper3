
def check_mod(username, password):
    valid_credentials = {
        "admin": "admin123",
        "user1": "password1",
        "moderator": "mod123",
        "testuser": "test456",
        "john": "john789"
    }
    
    if username is None or password is None:
        return "false"
    
    if username in valid_credentials and valid_credentials[username] == password:
        return "true"
    
    return "false"

if __name__ == "__main__":
    # Test case 1: Valid credentials - admin
    print("Test 1:", check_mod("admin", "admin123"))
    
    # Test case 2: Valid credentials - user1
    print("Test 2:", check_mod("user1", "password1"))
    
    # Test case 3: Invalid password
    print("Test 3:", check_mod("admin", "wrongpassword"))
    
    # Test case 4: Invalid username
    print("Test 4:", check_mod("nonexistent", "password"))
    
    # Test case 5: None values
    print("Test 5:", check_mod(None, None))
