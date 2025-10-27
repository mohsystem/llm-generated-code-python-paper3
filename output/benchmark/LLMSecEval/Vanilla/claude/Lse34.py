
class Lse34:
    def __init__(self):
        # Mock database
        self.database = {
            "admin": "admin123",
            "user1": "password1",
            "user2": "password2",
            "testuser": "testpass",
            "john": "doe123"
        }
    
    def login(self, username, password):
        if username is None or password is None:
            return "login"
        
        if username in self.database and self.database[username] == password:
            return "dashboard"
        else:
            return "login"


def main():
    lse = Lse34()
    
    # Test case 1: Valid credentials
    print("Test 1 - Valid user (admin/admin123):", lse.login("admin", "admin123"))
    
    # Test case 2: Invalid password
    print("Test 2 - Invalid password (admin/wrongpass):", lse.login("admin", "wrongpass"))
    
    # Test case 3: Non-existent user
    print("Test 3 - Non-existent user (unknown/pass):", lse.login("unknown", "pass"))
    
    # Test case 4: Valid credentials (user1)
    print("Test 4 - Valid user (user1/password1):", lse.login("user1", "password1"))
    
    # Test case 5: None credentials
    print("Test 5 - None credentials:", lse.login(None, None))


if __name__ == "__main__":
    main()
