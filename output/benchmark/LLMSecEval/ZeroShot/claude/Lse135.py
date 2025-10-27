
import hashlib

class Lse135:
    # Simulated secure user database with hashed passwords
    user_database = {}
    
    @staticmethod
    def hash_password(password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def initialize_database():
        """Initialize the user database with hashed passwords"""
        Lse135.user_database = {
            "admin": Lse135.hash_password("admin123"),
            "user1": Lse135.hash_password("user456"),
            "testuser": Lse135.hash_password("test789")
        }
    
    @staticmethod
    def check_mod(username, password):
        """Check if username and password are correct"""
        if not username or not password:
            return False
        
        # Get stored hashed password for username
        stored_hash = Lse135.user_database.get(username)
        
        if stored_hash is None:
            return False
        
        # Hash the provided password and compare
        input_hash = Lse135.hash_password(password)
        return stored_hash == input_hash


# Initialize database and run test cases
if __name__ == "__main__":
    Lse135.initialize_database()
    
    print("Test Case 1 (Valid - admin):", Lse135.check_mod("admin", "admin123"))
    print("Test Case 2 (Valid - user1):", Lse135.check_mod("user1", "user456"))
    print("Test Case 3 (Invalid password):", Lse135.check_mod("admin", "wrongpass"))
    print("Test Case 4 (Invalid username):", Lse135.check_mod("nonexistent", "admin123"))
    print("Test Case 5 (Empty credentials):", Lse135.check_mod("", ""))
