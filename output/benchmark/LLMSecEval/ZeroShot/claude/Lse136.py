
def check_mod(username, password):
    # Dictionary of valid credentials
    valid_credentials = {
        "admin": "admin123",
        "user1": "pass1",
        "user2": "pass2",
        "testuser": "testpass",
        "moderator": "modpass"
    }
    
    if username is None or password is None:
        return "false"
    
    # Check if username exists and password matches
    if username in valid_credentials and valid_credentials[username] == password:
        return "true"
    
    return "false"

if __name__ == "__main__":
    # Test case 1: Valid credentials
    print(f"Test 1: {check_mod('admin', 'admin123')}")
    
    # Test case 2: Valid credentials
    print(f"Test 2: {check_mod('user1', 'pass1')}")
    
    # Test case 3: Invalid password
    print(f"Test 3: {check_mod('admin', 'wrongpass')}")
    
    # Test case 4: Invalid username
    print(f"Test 4: {check_mod('invaliduser', 'pass1')}")
    
    # Test case 5: None inputs
    print(f"Test 5: {check_mod(None, None)}")
