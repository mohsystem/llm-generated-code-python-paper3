
import hashlib

class Lse39:
    # User database with hashed passwords
    user_database = {
        "admin": hashlib.sha256("admin123".encode()).hexdigest(),
        "user1": hashlib.sha256("password1".encode()).hexdigest(),
        "user2": hashlib.sha256("password2".encode()).hexdigest(),
        "testuser": hashlib.sha256("test123".encode()).hexdigest(),
        "john": hashlib.sha256("john456".encode()).hexdigest()
    }
    
    @staticmethod
    def hash_password(password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def login(username, password):
        """Secure login function"""
        # Input validation
        if not username or not password or not username.strip() or not password.strip():
            return "Error: Username or password cannot be empty"
        
        # Check if user exists and password matches
        stored_hash = Lse39.user_database.get(username)
        if stored_hash and stored_hash == Lse39.hash_password(password):
            return f"Success: Redirecting to session page for user: {username}"
        else:
            return "Error: Incorrect username or password"

def main():
    print("=== Secure Login System Test Cases ===\\n")
    
    # Test Case 1: Valid credentials
    print("Test Case 1: Valid login (admin/admin123)")
    print(Lse39.login("admin", "admin123"))
    print()
    
    # Test Case 2: Invalid password
    print("Test Case 2: Invalid password (admin/wrongpass)")
    print(Lse39.login("admin", "wrongpass"))
    print()
    
    # Test Case 3: Non-existent user
    print("Test Case 3: Non-existent user (hacker/hack123)")
    print(Lse39.login("hacker", "hack123"))
    print()
    
    # Test Case 4: Empty credentials
    print("Test Case 4: Empty username")
    print(Lse39.login("", "password"))
    print()
    
    # Test Case 5: Valid user2 login
    print("Test Case 5: Valid login (user2/password2)")
    print(Lse39.login("user2", "password2"))

if __name__ == "__main__":
    main()
