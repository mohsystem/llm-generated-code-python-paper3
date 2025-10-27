
import hashlib
import hmac
from typing import Dict, Optional

class Lse135:
    # Simulated secure credential storage with hashed passwords
    CREDENTIALS: Dict[str, str] = {
        "admin": None,
        "user1": None,
        "moderator": None
    }
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """Secure password hashing using SHA-256 (use bcrypt/scrypt in production)"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks"""
        return hmac.compare_digest(a.encode(), b.encode())
    
    @classmethod
    def _initialize_credentials(cls):
        """Initialize credentials with hashed passwords"""
        cls.CREDENTIALS["admin"] = cls._hash_password("Admin@123")
        cls.CREDENTIALS["user1"] = cls._hash_password("User@456")
        cls.CREDENTIALS["moderator"] = cls._hash_password("Mod@789")
    
    @classmethod
    def check_mod(cls, username: Optional[str], password: Optional[str]) -> bool:
        """\n        Securely validate username and password\n        \n        Args:\n            username: User's username\n            password: User's password\n            \n        Returns:\n            bool: True if credentials are valid, False otherwise\n        """
        # Input validation
        if not username or not password:
            return False
        
        if not isinstance(username, str) or not isinstance(password, str):
            return False
        
        username = username.strip()
        password = password.strip()
        
        if not username or not password:
            return False
        
        # Sanitize username (alphanumeric and underscore only)
        import re
        username = re.sub(r'[^a-zA-Z0-9_]', '', username)
        
        # Check if username exists
        if username not in cls.CREDENTIALS:
            # Perform dummy hash to prevent timing attacks
            cls._hash_password(password)
            return False
        
        # Hash the provided password and compare
        hashed_password = cls._hash_password(password)
        stored_hash = cls.CREDENTIALS[username]
        
        # Use constant-time comparison
        return cls._constant_time_compare(hashed_password, stored_hash)


# Initialize credentials
Lse135._initialize_credentials()


def main():
    """Main function with test cases"""
    print("=== Authentication Test Cases ===\\n")
    
    # Test case 1: Valid credentials
    print("Test 1 - Valid admin credentials:")
    print(f"Result: {Lse135.check_mod('admin', 'Admin@123')}")
    
    # Test case 2: Valid user credentials
    print("\\nTest 2 - Valid user1 credentials:")
    print(f"Result: {Lse135.check_mod('user1', 'User@456')}")
    
    # Test case 3: Invalid password
    print("\\nTest 3 - Invalid password:")
    print(f"Result: {Lse135.check_mod('admin', 'wrongpassword')}")
    
    # Test case 4: Non-existent user
    print("\\nTest 4 - Non-existent user:")
    print(f"Result: {Lse135.check_mod('hacker', 'password123')}")
    
    # Test case 5: Null/empty inputs
    print("\\nTest 5 - Empty credentials:")
    print(f"Result: {Lse135.check_mod('', '')}")


if __name__ == "__main__":
    main()
