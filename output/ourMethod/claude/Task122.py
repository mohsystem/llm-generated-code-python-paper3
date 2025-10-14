
import hashlib
import secrets
from typing import Dict, Optional, Tuple


class Task122:
    SALT_LENGTH: int = 16
    ITERATIONS: int = 210000
    KEY_LENGTH: int = 32
    
    def __init__(self) -> None:
        self.password_store: Dict[str, Tuple[bytes, bytes]] = {}
    
    def signup(self, username: str, password: str) -> bool:
        if not username or not isinstance(username, str) or len(username.strip()) == 0 or len(username) > 255:
            return False
        
        if not password or not isinstance(password, str) or len(password) < 8 or len(password) > 128:
            return False
        
        if username in self.password_store:
            return False
        
        try:
            salt = secrets.token_bytes(self.SALT_LENGTH)
            password_hash = self._hash_password(password, salt)
            self.password_store[username] = (salt, password_hash)
            return True
        except Exception:
            return False
    
    def verify_password(self, username: str, password: str) -> bool:
        if not username or not password:
            return False
        
        stored = self.password_store.get(username)
        if stored is None:
            return False
        
        salt, stored_hash = stored
        
        try:
            computed_hash = self._hash_password(password, salt)
            return self._constant_time_equals(computed_hash, stored_hash)
        except Exception:
            return False
    
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.ITERATIONS,
            dklen=self.KEY_LENGTH
        )
    
    def _constant_time_equals(self, a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0


def main() -> None:
    system = Task122()
    
    print("Test 1: Valid signup")
    result1 = system.signup("user1", "SecurePass123!")
    print(f"Signup user1: {result1}")
    
    print("\\nTest 2: Verify correct password")
    result2 = system.verify_password("user1", "SecurePass123!")
    print(f"Verify user1 correct password: {result2}")
    
    print("\\nTest 3: Verify incorrect password")
    result3 = system.verify_password("user1", "WrongPassword")
    print(f"Verify user1 wrong password: {result3}")
    
    print("\\nTest 4: Duplicate username")
    result4 = system.signup("user1", "AnotherPass456!")
    print(f"Signup duplicate user1: {result4}")
    
    print("\\nTest 5: Invalid password length")
    result5 = system.signup("user2", "short")
    print(f"Signup with short password: {result5}")


if __name__ == "__main__":
    main()
