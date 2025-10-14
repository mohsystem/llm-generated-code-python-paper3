
import hashlib
import secrets
import base64

class Task136:
    def __init__(self):
        self.user_database = {}
    
    def generate_salt(self):
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    def hash_password(self, password, salt):
        salt_bytes = base64.b64decode(salt)
        password_bytes = password.encode('utf-8')
        hasher = hashlib.sha256()
        hasher.update(salt_bytes + password_bytes)
        return base64.b64encode(hasher.digest()).decode('utf-8')
    
    def register_user(self, username, password):
        if not username or not password or len(password) < 8:
            return False
        
        if username in self.user_database:
            return False
        
        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        self.user_database[username] = {
            'salt': salt,
            'hashed_password': hashed_password
        }
        return True
    
    def authenticate_user(self, username, password):
        if not username or not password:
            return False
        
        if username not in self.user_database:
            return False
        
        credentials = self.user_database[username]
        hashed_password = self.hash_password(password, credentials['salt'])
        return hashed_password == credentials['hashed_password']


if __name__ == "__main__":
    auth_system = Task136()
    
    # Test Case 1: Successful registration and authentication
    print("Test 1 - Register and authenticate user:")
    registered = auth_system.register_user("alice", "SecurePass123")
    print(f"Registration: {registered}")
    authenticated = auth_system.authenticate_user("alice", "SecurePass123")
    print(f"Authentication: {authenticated}")
    print()
    
    # Test Case 2: Failed authentication with wrong password
    print("Test 2 - Wrong password:")
    wrong_pass = auth_system.authenticate_user("alice", "WrongPassword")
    print(f"Authentication: {wrong_pass}")
    print()
    
    # Test Case 3: Registration with weak password
    print("Test 3 - Weak password:")
    weak_pass = auth_system.register_user("bob", "weak")
    print(f"Registration: {weak_pass}")
    print()
    
    # Test Case 4: Duplicate username registration
    print("Test 4 - Duplicate username:")
    duplicate = auth_system.register_user("alice", "AnotherPass456")
    print(f"Registration: {duplicate}")
    print()
    
    # Test Case 5: Non-existent user authentication
    print("Test 5 - Non-existent user:")
    non_existent = auth_system.authenticate_user("charlie", "SomePassword789")
    print(f"Authentication: {non_existent}")
