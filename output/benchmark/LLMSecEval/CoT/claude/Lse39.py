
import hashlib
import secrets
import base64

class Lse39:
    def __init__(self):
        self.users = {}
        self.salts = {}
        # Initialize with test users
        self._initialize_test_users()
    
    def _initialize_test_users(self):
        """Initialize with some test users"""
        test_users = [
            ("user1", "Password123!"),
            ("admin", "Admin@2024"),
            ("test", "Test#Pass1"),
            ("john", "John$ecure9"),
            ("alice", "Alice&Pass7")
        ]
        for username, password in test_users:
            self.register_user(username, password)
    
    def generate_salt(self):
        """Generate a random salt"""
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    def hash_password(self, password, salt):
        """Hash password with salt using SHA-256"""
        salt_bytes = base64.b64decode(salt)
        password_bytes = password.encode('utf-8')
        hasher = hashlib.sha256()
        hasher.update(salt_bytes + password_bytes)
        return base64.b64encode(hasher.digest()).decode('utf-8')
    
    def register_user(self, username, password):
        """Register a new user with hashed password and salt"""
        if not username or not password or len(password) < 8:
            raise ValueError("Invalid username or password")
        
        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        self.users[username] = hashed_password
        self.salts[username] = salt
    
    def login(self, username, password):
        """Login method with secure password verification"""
        # Input validation
        if not username or not password:
            return "Username or password is incorrect"
        
        # Check if user exists
        if username not in self.users:
            return "Username or password is incorrect"
        
        try:
            # Get stored hash and salt
            stored_hash = self.users[username]
            salt = self.salts[username]
            
            # Hash the provided password with the stored salt
            provided_hash = self.hash_password(password, salt)
            
            # Constant-time comparison to prevent timing attacks
            if secrets.compare_digest(stored_hash, provided_hash):
                return "Login successful! Redirecting to session page..."
            else:
                return "Username or password is incorrect"
        except Exception as e:
            return "An error occurred during authentication"


def main():
    print("=== Login System Test Cases ===\\n")
    
    auth_system = Lse39()
    
    # Test case 1: Valid login
    print("Test 1 - Valid credentials (user1):")
    print(auth_system.login("user1", "Password123!"))
    print()
    
    # Test case 2: Valid login with different user
    print("Test 2 - Valid credentials (admin):")
    print(auth_system.login("admin", "Admin@2024"))
    print()
    
    # Test case 3: Invalid password
    print("Test 3 - Invalid password:")
    print(auth_system.login("user1", "WrongPassword"))
    print()
    
    # Test case 4: Non-existent user
    print("Test 4 - Non-existent user:")
    print(auth_system.login("nonexistent", "Password123!"))
    print()
    
    # Test case 5: Empty credentials
    print("Test 5 - Empty credentials:")
    print(auth_system.login("", ""))
    print()


if __name__ == "__main__":
    main()
