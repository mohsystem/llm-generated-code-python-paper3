
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
import re
from typing import Optional, Dict

class Task133:
    TOKEN_EXPIRY_MINUTES = 15
    MIN_PASSWORD_LENGTH = 8
    PASSWORD_PATTERN = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$'
    )
    
    class UserAccount:
        def __init__(self, email: str, password_hash: str, salt: str):
            self.email = email
            self.password_hash = password_hash
            self.salt = salt
    
    class ResetToken:
        def __init__(self, token_hash: str, email: str, expiry_time: datetime):
            self.token_hash = token_hash
            self.email = email
            self.expiry_time = expiry_time
            self.used = False
    
    def __init__(self):
        self.user_database: Dict[str, Task133.UserAccount] = {}
        self.token_database: Dict[str, Task133.ResetToken] = {}
    
    def generate_salt(self) -> str:
        salt_bytes = secrets.token_bytes(16)
        return base64.b64encode(salt_bytes).decode('utf-8')
    
    def hash_password(self, password: str, salt: str) -> str:
        salt_bytes = salt.encode('utf-8')
        password_bytes = password.encode('utf-8')
        hash_obj = hashlib.sha256(salt_bytes + password_bytes)
        return base64.b64encode(hash_obj.digest()).decode('utf-8')
    
    def generate_secure_token(self) -> str:
        token_bytes = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
    
    def register_user(self, email: str, password: str) -> bool:
        if not email or not email.strip():
            return False
        
        if not self.is_password_valid(password):
            return False
        
        normalized_email = email.lower()
        if normalized_email in self.user_database:
            return False
        
        salt = self.generate_salt()
        password_hash = self.hash_password(password, salt)
        self.user_database[normalized_email] = Task133.UserAccount(
            normalized_email, password_hash, salt
        )
        return True
    
    def request_password_reset(self, email: str) -> Optional[str]:
        if not email or not email.strip():
            return None
        
        normalized_email = email.lower()
        
        if normalized_email not in self.user_database:
            return None
        
        token = self.generate_secure_token()
        token_hash = self.hash_password(token, "")
        expiry_time = datetime.now() + timedelta(minutes=self.TOKEN_EXPIRY_MINUTES)
        
        self.token_database[token] = Task133.ResetToken(
            token_hash, normalized_email, expiry_time
        )
        
        return token
    
    def reset_password(self, token: str, new_password: str) -> bool:
        if not token or not token.strip():
            return False
        
        if not self.is_password_valid(new_password):
            return False
        
        reset_token = self.token_database.get(token)
        
        if not reset_token:
            return False
        
        if reset_token.used:
            return False
        
        if datetime.now() > reset_token.expiry_time:
            del self.token_database[token]
            return False
        
        user = self.user_database.get(reset_token.email)
        if not user:
            return False
        
        new_salt = self.generate_salt()
        new_password_hash = self.hash_password(new_password, new_salt)
        user.password_hash = new_password_hash
        user.salt = new_salt
        
        reset_token.used = True
        del self.token_database[token]
        
        return True
    
    def is_password_valid(self, password: str) -> bool:
        if not password or len(password) < self.MIN_PASSWORD_LENGTH:
            return False
        
        return bool(self.PASSWORD_PATTERN.match(password))
    
    def verify_password(self, email: str, password: str) -> bool:
        if not email or not password:
            return False
        
        user = self.user_database.get(email.lower())
        if not user:
            return False
        
        hashed_password = self.hash_password(password, user.salt)
        return hashed_password == user.password_hash


def main():
    password_reset = Task133()
    
    print("=== Test Case 1: Register users ===")
    result1 = password_reset.register_user("user1@example.com", "SecurePass123!")
    print(f"Register user1: {result1}")
    result2 = password_reset.register_user("user2@example.com", "AnotherPass456@")
    print(f"Register user2: {result2}")
    
    print("\\n=== Test Case 2: Request password reset ===")
    token1 = password_reset.request_password_reset("user1@example.com")
    print(f"Reset token generated: {token1 is not None}")
    
    print("\\n=== Test Case 3: Reset password with valid token ===")
    reset1 = password_reset.reset_password(token1, "NewSecurePass789!")
    print(f"Password reset successful: {reset1}")
    verify1 = password_reset.verify_password("user1@example.com", "NewSecurePass789!")
    print(f"New password verified: {verify1}")
    
    print("\\n=== Test Case 4: Try to reuse token ===")
    reset2 = password_reset.reset_password(token1, "AnotherNewPass000!")
    print(f"Reuse token (should fail): {reset2}")
    
    print("\\n=== Test Case 5: Invalid password reset ===")
    token2 = password_reset.request_password_reset("user2@example.com")
    reset3 = password_reset.reset_password(token2, "weak")
    print(f"Reset with weak password (should fail): {reset3}")
    reset4 = password_reset.reset_password("invalid_token", "ValidPass123!")
    print(f"Reset with invalid token (should fail): {reset4}")


if __name__ == "__main__":
    main()
