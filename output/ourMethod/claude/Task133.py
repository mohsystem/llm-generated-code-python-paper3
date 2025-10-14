
import secrets
import hashlib
import hmac
import re
import time
from typing import Dict, Optional, Tuple
from base64 import urlsafe_b64encode

SALT_LENGTH = 16
PBKDF2_ITERATIONS = 210000
TOKEN_LENGTH = 32
TOKEN_EXPIRY_MS = 3600000  # 1 hour

PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$'
)


class User:
    def __init__(self, username: str, password_hash: bytes, salt: bytes):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt


class ResetToken:
    def __init__(self, username: str, token_hash: bytes, expiry_time: int):
        self.username = username
        self.token_hash = token_hash
        self.expiry_time = expiry_time


class PasswordResetSystem:
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.reset_tokens: Dict[str, ResetToken] = {}
    
    def _generate_salt(self) -> bytes:
        return secrets.token_bytes(SALT_LENGTH)
    
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PBKDF2_ITERATIONS,
            dklen=32
        )
    
    def _validate_password(self, password: str) -> bool:
        if not password or len(password) < 12 or len(password) > 128:
            return False
        return bool(PASSWORD_PATTERN.match(password))
    
    def _constant_time_equals(self, a: bytes, b: bytes) -> bool:
        if not a or not b or len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    def register_user(self, username: str, password: str) -> str:
        if not username or not username.strip() or len(username) > 50:
            return "Error: Invalid username"
        
        username = username.strip()
        
        if not self._validate_password(password):
            return "Error: Password must be 12-128 characters with uppercase, lowercase, digit, and special character"
        
        if username in self.users:
            return "Error: User already exists"
        
        try:
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)
            self.users[username] = User(username, password_hash, salt)
            return "Success: User registered"
        except Exception:
            return "Error: Registration failed"
    
    def request_password_reset(self, username: str) -> str:
        if not username or not username.strip():
            return "Error: Invalid username"
        
        username = username.strip()
        
        if username not in self.users:
            return "Error: User not found"
        
        try:
            token_bytes = secrets.token_bytes(TOKEN_LENGTH)
            token = urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
            
            token_hash = hashlib.sha256(token.encode('utf-8')).digest()
            
            expiry_time = int(time.time() * 1000) + TOKEN_EXPIRY_MS
            self.reset_tokens[username] = ResetToken(username, token_hash, expiry_time)
            
            return f"Success: Reset token generated: {token}"
        except Exception:
            return "Error: Token generation failed"
    
    def reset_password(self, username: str, token: str, new_password: str) -> str:
        if not username or not username.strip():
            return "Error: Invalid username"
        
        if not token or not token.strip():
            return "Error: Invalid token"
        
        username = username.strip()
        token = token.strip()
        
        if not self._validate_password(new_password):
            return "Error: Password must be 12-128 characters with uppercase, lowercase, digit, and special character"
        
        if username not in self.users:
            return "Error: User not found"
        
        if username not in self.reset_tokens:
            return "Error: No reset token found"
        
        reset_token = self.reset_tokens[username]
        
        current_time = int(time.time() * 1000)
        if current_time > reset_token.expiry_time:
            del self.reset_tokens[username]
            return "Error: Token expired"
        
        try:
            provided_token_hash = hashlib.sha256(token.encode('utf-8')).digest()
            
            if not self._constant_time_equals(provided_token_hash, reset_token.token_hash):
                return "Error: Invalid token"
            
            new_salt = self._generate_salt()
            new_hash = self._hash_password(new_password, new_salt)
            
            user = self.users[username]
            user.password_hash = new_hash
            user.salt = new_salt
            
            del self.reset_tokens[username]
            
            return "Success: Password reset successfully"
        except Exception:
            return "Error: Password reset failed"
    
    def verify_login(self, username: str, password: str) -> str:
        if not username or not username.strip() or not password:
            return "Error: Invalid credentials"
        
        username = username.strip()
        
        if username not in self.users:
            return "Error: Invalid credentials"
        
        try:
            user = self.users[username]
            password_hash = self._hash_password(password, user.salt)
            
            if self._constant_time_equals(password_hash, user.password_hash):
                return "Success: Login successful"
            else:
                return "Error: Invalid credentials"
        except Exception:
            return "Error: Login failed"


def main():
    system = PasswordResetSystem()
    
    print("Test 1: Register user")
    print(system.register_user("alice", "SecurePass123!@#"))
    
    print("\\nTest 2: Request password reset")
    reset_response = system.request_password_reset("alice")
    print(reset_response)
    
    if reset_response.startswith("Success"):
        token = reset_response.split(": ")[-1]
        
        print("\\nTest 3: Reset password with valid token")
        print(system.reset_password("alice", token, "NewSecurePass456!@#"))
        
        print("\\nTest 4: Verify login with new password")
        print(system.verify_login("alice", "NewSecurePass456!@#"))
    
    print("\\nTest 5: Attempt reset with invalid token")
    print(system.reset_password("alice", "invalidtoken123", "AnotherPass789!@#"))


if __name__ == "__main__":
    main()
