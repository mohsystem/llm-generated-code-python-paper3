
user_database = {
    "admin": "admin123",
    "user1": "password1",
    "user2": "password2",
    "testuser": "test123",
    "john": "doe456"
}

def login(username, password):
    if username is None or password is None:
        return "Username or password is incorrect"
    
    if username in user_database and user_database[username] == password:
        return "Login successful! Redirecting to session page..."
    else:
        return "Username or password is incorrect"

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    print(login("admin", "admin123"))
    print()
    
    print("Test Case 2:")
    print(login("user1", "wrongpassword"))
    print()
    
    print("Test Case 3:")
    print(login("nonexistent", "password"))
    print()
    
    print("Test Case 4:")
    print(login("testuser", "test123"))
    print()
    
    print("Test Case 5:")
    print(login("john", "doe456"))
