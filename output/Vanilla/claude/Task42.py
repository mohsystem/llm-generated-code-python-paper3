
import hashlib
import secrets
import base64

class Task42:
    def __init__(self):
        self.users = {}
    
    class UserCredential:
        def __init__(self, salt, hashed_password):
            self.salt = salt
            self.hashed_password = hashed_password
    
    def generate_salt(self):
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    def hash_password(self, password, salt):
        salt_bytes = base64.b64decode(salt)
        password_bytes = password.encode('utf-8')
        hashed = hashlib.sha256(salt_bytes + password_bytes).digest()
        return base64.b64encode(hashed).decode('utf-8')
    
    def register_user(self, username, password):
        if username in self.users:
            return False
        
        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        self.users[username] = self.UserCredential(salt, hashed_password)
        return True
    
    def authenticate_user(self, username, password):
        if username not in self.users:
            return False
        
        credential = self.users[username]
        hashed_password = self.hash_password(password, credential.salt)
        return hashed_password == credential.hashed_password
    
    def delete_user(self, username):
        if username not in self.users:
            return False
        del self.users[username]
        return True
    
    def change_password(self, username, old_password, new_password):
        if not self.authenticate_user(username, old_password):
            return False
        
        salt = self.generate_salt()
        hashed_password = self.hash_password(new_password, salt)
        self.users[username] = self.UserCredential(salt, hashed_password)
        return True


if __name__ == "__main__":
    auth_system = Task42()
    
    # Test Case 1: Register new user
    print("Test 1 - Register user 'alice':")
    result1 = auth_system.register_user("alice", "password123")
    print(f"Registration successful: {result1}")
    
    # Test Case 2: Authenticate with correct password
    print("\\nTest 2 - Authenticate alice with correct password:")
    result2 = auth_system.authenticate_user("alice", "password123")
    print(f"Authentication successful: {result2}")
    
    # Test Case 3: Authenticate with incorrect password
    print("\\nTest 3 - Authenticate alice with incorrect password:")
    result3 = auth_system.authenticate_user("alice", "wrongpassword")
    print(f"Authentication successful: {result3}")
    
    # Test Case 4: Change password
    print("\\nTest 4 - Change password for alice:")
    result4 = auth_system.change_password("alice", "password123", "newpassword456")
    print(f"Password change successful: {result4}")
    result4b = auth_system.authenticate_user("alice", "newpassword456")
    print(f"Authentication with new password: {result4b}")
    
    # Test Case 5: Register duplicate user and delete user
    print("\\nTest 5 - Register duplicate user and delete:")
    result5a = auth_system.register_user("alice", "anotherpassword")
    print(f"Duplicate registration blocked: {not result5a}")
    result5b = auth_system.delete_user("alice")
    print(f"User deletion successful: {result5b}")
    result5c = auth_system.authenticate_user("alice", "newpassword456")
    print(f"Authentication after deletion: {result5c}")
