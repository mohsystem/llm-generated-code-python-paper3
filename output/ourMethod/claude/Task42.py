
import secrets
import hashlib
from typing import Dict, Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class UserAuthSystem:
    SALT_LENGTH = 16
    PBKDF2_ITERATIONS = 210000
    HASH_LENGTH = 32
    
    def __init__(self):
        self.user_database: Dict[str, bytes] = {}
    
    def register_user(self, username: str, password: str) -> bool:
        if not username or len(username) > 100:
            return False
        if not password or len(password) < 8 or len(password) > 128:
            return False
        if username in self.user_database:
            return False
        
        try:
            hashed_password = self._hash_password(password)
            self.user_database[username] = hashed_password
            return True
        except Exception:
            return False
    
    def authenticate_user(self, username: str, password: str) -> bool:
        if not username or not password:
            return False
        
        stored_hash = self.user_database.get(username)
        if stored_hash is None:
            dummy_salt = secrets.token_bytes(self.SALT_LENGTH)
            try:
                self._derive_key(password, dummy_salt)
            except Exception:
                pass
            return False
        
        try:
            return self._verify_password(password, stored_hash)
        except Exception:
            return False
    
    def _hash_password(self, password: str) -> bytes:
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = self._derive_key(password, salt)
        return salt + key
    
    def _verify_password(self, password: str, stored_data: bytes) -> bool:
        if len(stored_data) < self.SALT_LENGTH + self.HASH_LENGTH:
            return False
        
        salt = stored_data[:self.SALT_LENGTH]
        stored_hash = stored_data[self.SALT_LENGTH:]
        
        computed_hash = self._derive_key(password, salt)
        
        return self._constant_time_compare(stored_hash, computed_hash)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.HASH_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0


def main():
    auth = UserAuthSystem()
    
    print("Test 1 - Register valid user:")
    test1 = auth.register_user("alice", "SecurePass123!")
    print(f"Registration successful: {test1}")
    
    print("\\nTest 2 - Authenticate with correct password:")
    test2 = auth.authenticate_user("alice", "SecurePass123!")
    print(f"Authentication successful: {test2}")
    
    print("\\nTest 3 - Authenticate with wrong password:")
    test3 = auth.authenticate_user("alice", "WrongPassword")
    print(f"Authentication successful (should be False): {test3}")
    
    print("\\nTest 4 - Register duplicate user:")
    test4 = auth.register_user("alice", "AnotherPass456")
    print(f"Registration successful (should be False): {test4}")
    
    print("\\nTest 5 - Authenticate non-existent user:")
    test5 = auth.authenticate_user("bob", "SomePassword")
    print(f"Authentication successful (should be False): {test5}")


if __name__ == "__main__":
    main()
