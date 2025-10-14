
import hashlib

class Task136:
    def __init__(self):
        self.user_database = {}
    
    def register_user(self, username, password):
        if not username or not password:
            return False
        if username in self.user_database:
            return False
        hashed_password = self._hash_password(password)
        self.user_database[username] = hashed_password
        return True
    
    def authenticate_user(self, username, password):
        if not username or not password or username not in self.user_database:
            return False
        hashed_password = self._hash_password(password)
        return self.user_database[username] == hashed_password
    
    def delete_user(self, username):
        if not username or username not in self.user_database:
            return False
        del self.user_database[username]
        return True
    
    def change_password(self, username, old_password, new_password):
        if not self.authenticate_user(username, old_password):
            return False
        hashed_password = self._hash_password(new_password)
        self.user_database[username] = hashed_password
        return True
    
    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()


if __name__ == "__main__":
    auth = Task136()
    
    # Test Case 1: Register a new user
    print(f"Test 1 - Register user 'john': {auth.register_user('john', 'password123')}")
    
    # Test Case 2: Authenticate with correct credentials
    print(f"Test 2 - Authenticate 'john' with correct password: {auth.authenticate_user('john', 'password123')}")
    
    # Test Case 3: Authenticate with incorrect credentials
    print(f"Test 3 - Authenticate 'john' with wrong password: {auth.authenticate_user('john', 'wrongpassword')}")
    
    # Test Case 4: Register duplicate user
    print(f"Test 4 - Register duplicate user 'john': {auth.register_user('john', 'newpassword')}")
    
    # Test Case 5: Change password
    print(f"Test 5 - Change password for 'john': {auth.change_password('john', 'password123', 'newpassword123')}")
    print(f"Test 5 - Authenticate with new password: {auth.authenticate_user('john', 'newpassword123')}")
