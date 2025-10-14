
import hashlib
import secrets
import base64
from typing import Dict, Optional

class Task42:
    SALT_LENGTH = 16
    MAX_LOGIN_ATTEMPTS = 3
    
    class UserCredentials:
        def __init__(self, password_hash: str, salt: str):
            self.password_hash = password_hash
            self.salt = salt
    
    def __init__(self):
        self.user_database: Dict[str, Task42.UserCredentials] = {}
        self.login_attempts: Dict[str, int] = {}
    
    def generate_salt(self) -> str:
        salt = secrets.token_bytes(self.SALT_LENGTH)
        return base64.b64encode(salt).decode('utf-8')
    
    def hash_password(self, password: str, salt: str) -> str:
        salt_bytes = base64.b64decode(salt.encode('utf-8'))
        password_bytes = password.encode('utf-8')
        hasher = hashlib.sha256()
        hasher.update(salt_bytes)
        hasher.update(password_bytes)
        hashed_password = hasher.digest()
        return base64.b64encode(hashed_password).decode('utf-8')
    
    def register_user(self, username: str, password: str) -> bool:
        if not username or not username.strip() or not password or len(password) < 8:
            return False
        
        if username in self.user_database:
            return False
        
        salt = self.generate_salt()
        password_hash = self.hash_password(password, salt)
        self.user_database[username] = self.UserCredentials(password_hash, salt)
        self.login_attempts[username] = 0
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        if not username or not password:
            return False
        
        if username not in self.user_database:
            return False
        
        attempts = self.login_attempts.get(username, 0)
        if attempts >= self.MAX_LOGIN_ATTEMPTS:
            return False
        
        credentials = self.user_database[username]
        password_hash = self.hash_password(password, credentials.salt)
        
        if password_hash == credentials.password_hash:
            self.login_attempts[username] = 0
            return True
        else:
            self.login_attempts[username] = attempts + 1
            return False
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        if not self.authenticate_user(username, old_password):
            return False
        
        if not new_password or len(new_password) < 8:
            return False
        
        salt = self.generate_salt()
        password_hash = self.hash_password(new_password, salt)
        self.user_database[username] = self.UserCredentials(password_hash, salt)
        return True
    
    def reset_login_attempts(self, username: str) -> None:
        if username in self.user_database:
            self.login_attempts[username] = 0


def main():
    auth_system = Task42()
    
    print("Test Case 1: User Registration")
    result1 = auth_system.register_user("alice", "SecurePass123")
    print(f"Register alice: {'SUCCESS' if result1 else 'FAILED'}")
    
    print("\\nTest Case 2: Successful Authentication")
    result2 = auth_system.authenticate_user("alice", "SecurePass123")
    print(f"Authenticate alice: {'SUCCESS' if result2 else 'FAILED'}")
    
    print("\\nTest Case 3: Failed Authentication (wrong password)")
    result3 = auth_system.authenticate_user("alice", "WrongPass123")
    print(f"Authenticate with wrong password: {'SUCCESS' if result3 else 'FAILED'}")
    
    print("\\nTest Case 4: Password Change")
    result4 = auth_system.change_password("alice", "SecurePass123", "NewSecure456")
    print(f"Change password: {'SUCCESS' if result4 else 'FAILED'}")
    result4b = auth_system.authenticate_user("alice", "NewSecure456")
    print(f"Authenticate with new password: {'SUCCESS' if result4b else 'FAILED'}")
    
    print("\\nTest Case 5: Account Lockout after multiple failed attempts")
    auth_system.register_user("bob", "BobPass123")
    auth_system.authenticate_user("bob", "wrong1")
    auth_system.authenticate_user("bob", "wrong2")
    auth_system.authenticate_user("bob", "wrong3")
    result5 = auth_system.authenticate_user("bob", "BobPass123")
    print(f"Authenticate after 3 failed attempts: {'SUCCESS' if result5 else 'FAILED (LOCKED)'}")


if __name__ == "__main__":
    main()
