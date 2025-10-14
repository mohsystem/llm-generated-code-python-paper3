
import hashlib
import secrets
import base64

class Task122:
    def __init__(self):
        self.user_database = {}
    
    def generate_salt(self):
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    def hash_password(self, password, salt):
        salt_bytes = base64.b64decode(salt)
        return base64.b64encode(
            hashlib.sha256(salt_bytes + password.encode()).digest()
        ).decode('utf-8')
    
    def signup(self, username, password):
        if not username or not username.strip():
            return "Error: Username cannot be empty"
        if not password or len(password) < 6:
            return "Error: Password must be at least 6 characters"
        if username in self.user_database:
            return "Error: Username already exists"
        
        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        self.user_database[username] = {
            'username': username,
            'hashed_password': hashed_password,
            'salt': salt
        }
        return f"Success: User {username} registered successfully"
    
    def verify_password(self, username, password):
        if username not in self.user_database:
            return False
        user = self.user_database[username]
        hashed_input = self.hash_password(password, user['salt'])
        return hashed_input == user['hashed_password']


if __name__ == "__main__":
    system = Task122()
    
    print("Test Case 1: Valid signup")
    print(system.signup("john_doe", "password123"))
    
    print("\\nTest Case 2: Duplicate username")
    print(system.signup("john_doe", "newpassword456"))
    
    print("\\nTest Case 3: Weak password")
    print(system.signup("jane_doe", "123"))
    
    print("\\nTest Case 4: Empty username")
    print(system.signup("", "password123"))
    
    print("\\nTest Case 5: Multiple valid signups and verification")
    print(system.signup("alice", "securePass789"))
    print(system.signup("bob", "myPassword!"))
    print(f"Verify alice password: {system.verify_password('alice', 'securePass789')}")
    print(f"Verify bob wrong password: {system.verify_password('bob', 'wrongPass')}")
