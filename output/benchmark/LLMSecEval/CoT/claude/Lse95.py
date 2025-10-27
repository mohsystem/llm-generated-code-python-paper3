
import hashlib
import secrets
import base64
from typing import Tuple

class Lse95:
    ITERATIONS = 100000
    SALT_LENGTH = 16
    
    @staticmethod
    def register_user(username: str, password: str) -> Tuple[str, str]:
        salt = Lse95.generate_salt()
        password_hash = Lse95.hash_password(password, salt)
        
        salt_base64 = base64.b64encode(salt).decode('utf-8')
        hash_base64 = base64.b64encode(password_hash).decode('utf-8')
        stored_password = f"{salt_base64}:{hash_base64}"
        
        return username, stored_password
    
    @staticmethod
    def verify_password(password: str, stored_password: str) -> bool:
        parts = stored_password.split(':')
        if len(parts) != 2:
            return False
        
        salt = base64.b64decode(parts[0])
        stored_hash = base64.b64decode(parts[1])
        computed_hash = Lse95.hash_password(password, salt)
        
        return Lse95.slow_equals(stored_hash, computed_hash)
    
    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(Lse95.SALT_LENGTH)
    
    @staticmethod
    def hash_password(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, Lse95.ITERATIONS)
    
    @staticmethod
    def slow_equals(a: bytes, b: bytes) -> bool:
        return secrets.compare_digest(a, b)

if __name__ == "__main__":
    # Test Case 1: Basic registration
    user1, pass1 = Lse95.register_user("alice", "SecurePass123!")
    print(f"Test 1 - Registered: {user1}")
    print(f"Verification: {Lse95.verify_password('SecurePass123!', pass1)}")
    
    # Test Case 2: Different user
    user2, pass2 = Lse95.register_user("bob", "MyPassword456@")
    print(f"\\nTest 2 - Registered: {user2}")
    print(f"Verification: {Lse95.verify_password('MyPassword456@', pass2)}")
    
    # Test Case 3: Wrong password
    print(f"\\nTest 3 - Wrong password: {Lse95.verify_password('WrongPass', pass1)}")
    
    # Test Case 4: Complex password
    user3, pass3 = Lse95.register_user("charlie", "C0mpl3x!P@ssw0rd#2024")
    print(f"\\nTest 4 - Registered: {user3}")
    print(f"Verification: {Lse95.verify_password('C0mpl3x!P@ssw0rd#2024', pass3)}")
    
    # Test Case 5: Another user
    user4, pass4 = Lse95.register_user("david", "AnotherSecure987$")
    print(f"\\nTest 5 - Registered: {user4}")
    print(f"Verification: {Lse95.verify_password('AnotherSecure987$', pass4)}")
