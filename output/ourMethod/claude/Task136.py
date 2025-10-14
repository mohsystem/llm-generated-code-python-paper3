
import os
import secrets
from typing import Optional, Dict
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac

class Task136:
    SALT_LENGTH = 16
    ITERATIONS = 210000
    KEY_LENGTH = 32
    
    def __init__(self):
        self.user_database: Dict[str, Dict[str, bytes]] = {}
    
    def register_user(self, username: str, password: str) -> bool:
        if not username or not isinstance(username, str) or len(username.strip()) == 0 or len(username) > 100:
            return False
        if not password or not isinstance(password, str) or len(password) < 8 or len(password) > 128:
            return False
        
        username = username.strip()
        
        if username in self.user_database:
            return False
        
        salt = secrets.token_bytes(self.SALT_LENGTH)
        password_hash = self._hash_password(password, salt)
        
        if password_hash is None:
            return False
        
        self.user_database[username] = {
            'password_hash': password_hash,
            'salt': salt
        }
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        if not username or not isinstance(username, str) or len(username.strip()) == 0 or len(username) > 100:
            return False
        if not password or not isinstance(password, str) or len(password) < 8 or len(password) > 128:
            return False
        
        username = username.strip()
        
        if username not in self.user_database:
            return False
        
        credentials = self.user_database[username]
        computed_hash = self._hash_password(password, credentials['salt'])
        
        if computed_hash is None:
            return False
        
        return hmac.compare_digest(computed_hash, credentials['password_hash'])
    
    def _hash_password(self, password: str, salt: bytes) -> Optional[bytes]:
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_LENGTH,
                salt=salt,
                iterations=self.ITERATIONS,
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception:
            return None
    
    def delete_user(self, username: str) -> bool:
        if not username or not isinstance(username, str) or len(username.strip()) == 0:
            return False
        username = username.strip()
        if username in self.user_database:
            del self.user_database[username]
            return True
        return False
    
    def user_exists(self, username: str) -> bool:
        if not username or not isinstance(username, str) or len(username.strip()) == 0:
            return False
        return username.strip() in self.user_database


def main():
    auth = Task136()
    
    # Test case 1: Register and authenticate valid user
    print("Test 1 - Register and authenticate:")
    registered1 = auth.register_user("alice", "SecurePass123!")
    authenticated1 = auth.authenticate_user("alice", "SecurePass123!")
    print(f"Registered: {registered1}, Authenticated: {authenticated1}")
    
    # Test case 2: Authenticate with wrong password
    print("\\nTest 2 - Wrong password:")
    authenticated2 = auth.authenticate_user("alice", "WrongPassword")
    print(f"Authenticated with wrong password: {authenticated2}")
    
    # Test case 3: Register duplicate user
    print("\\nTest 3 - Duplicate registration:")
    registered3 = auth.register_user("alice", "AnotherPass456!")
    print(f"Duplicate registration: {registered3}")
    
    # Test case 4: Authenticate non-existent user
    print("\\nTest 4 - Non-existent user:")
    authenticated4 = auth.authenticate_user("bob", "SomePass789!")
    print(f"Non-existent user authenticated: {authenticated4}")
    
    # Test case 5: Invalid input validation
    print("\\nTest 5 - Invalid inputs:")
    registered5a = auth.register_user("", "password123")
    registered5b = auth.register_user("charlie", "short")
    registered5c = auth.register_user(None, "password123") if None else auth.register_user("", "password123")
    print(f"Empty username: {registered5a}, Short password: {registered5b}, Invalid username: {registered5c}")


if __name__ == "__main__":
    main()
