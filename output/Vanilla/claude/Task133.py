
import hashlib
import time
import random

class Task133:
    class User:
        def __init__(self, username, email, password_hash):
            self.username = username
            self.email = email
            self.password_hash = password_hash
    
    class ResetToken:
        def __init__(self, token, username, expiry_time):
            self.token = token
            self.username = username
            self.expiry_time = expiry_time
        
        def is_valid(self):
            return time.time() * 1000 < self.expiry_time
    
    def __init__(self):
        self.users = {}
        self.reset_tokens = {}
    
    def register_user(self, username, email, password):
        if username in self.users:
            return False
        password_hash = self.hash_password(password)
        self.users[username] = self.User(username, email, password_hash)
        return True
    
    def request_password_reset(self, username):
        if username not in self.users:
            return None
        
        token = self.generate_token(username)
        expiry_time = time.time() * 1000 + 3600000  # 1 hour
        self.reset_tokens[token] = self.ResetToken(token, username, expiry_time)
        return token
    
    def reset_password(self, token, new_password):
        if token not in self.reset_tokens:
            return False
        
        reset_token = self.reset_tokens[token]
        if not reset_token.is_valid():
            del self.reset_tokens[token]
            return False
        
        if reset_token.username not in self.users:
            return False
        
        user = self.users[reset_token.username]
        user.password_hash = self.hash_password(new_password)
        del self.reset_tokens[token]
        return True
    
    def verify_password(self, username, password):
        if username not in self.users:
            return False
        user = self.users[username]
        return user.password_hash == self.hash_password(password)
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def generate_token(self, username):
        data = username + str(time.time()) + str(random.random())
        return self.hash_password(data)[:32]


if __name__ == "__main__":
    password_reset = Task133()
    
    # Test Case 1: Register a user and verify password
    print("Test Case 1: Register user")
    registered = password_reset.register_user("john_doe", "john@example.com", "password123")
    print(f"User registered: {registered}")
    print(f"Password verified: {password_reset.verify_password('john_doe', 'password123')}")
    print()
    
    # Test Case 2: Request password reset
    print("Test Case 2: Request password reset")
    token = password_reset.request_password_reset("john_doe")
    print(f"Reset token generated: {token is not None}")
    print()
    
    # Test Case 3: Reset password with valid token
    print("Test Case 3: Reset password with valid token")
    reset_success = password_reset.reset_password(token, "newPassword456")
    print(f"Password reset successful: {reset_success}")
    print(f"Old password verified: {password_reset.verify_password('john_doe', 'password123')}")
    print(f"New password verified: {password_reset.verify_password('john_doe', 'newPassword456')}")
    print()
    
    # Test Case 4: Try to reset with invalid token
    print("Test Case 4: Reset with invalid token")
    invalid_reset = password_reset.reset_password("invalidtoken123", "anotherPassword")
    print(f"Reset with invalid token: {invalid_reset}")
    print()
    
    # Test Case 5: Request reset for non-existent user
    print("Test Case 5: Request reset for non-existent user")
    invalid_token = password_reset.request_password_reset("non_existent_user")
    print(f"Token for non-existent user: {invalid_token is not None}")
