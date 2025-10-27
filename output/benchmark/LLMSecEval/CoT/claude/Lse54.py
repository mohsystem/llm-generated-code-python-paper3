
import hashlib
import secrets
import base64
import re

class Lse54:
    user_database = {}
    salts = {}
    
    @classmethod
    def initialize(cls):
        # Initialize with secure password hashing
        salt = cls.generate_salt()
        cls.salts['admin'] = salt
        cls.user_database['admin'] = cls.hash_password('admin123', salt)
    
    @staticmethod
    def login():
        """GET request - returns login form HTML"""
        return """<!DOCTYPE html>\n<html>\n<head><title>Login</title></head>\n<body>\n<h2>Login Form</h2>\n<form method='POST' action='/do_login'>\n  <label>Username: <input type='text' name='username' required pattern='[a-zA-Z0-9_]{3,20}'></label><br>\n  <label>Password: <input type='password' name='password' required minlength='6'></label><br>\n  <input type='submit' value='Login'>\n</form>\n</body>\n</html>"""
    
    @classmethod
    def do_login(cls, username, password):
        """POST request - processes login"""
        # Input validation
        if not username or not password or not username.strip() or not password.strip():
            return "Invalid credentials"
        
        # Sanitize username (alphanumeric and underscore only)
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return "Invalid username format"
        
        # Check if user exists and verify password
        if username in cls.user_database:
            salt = cls.salts.get(username)
            hashed_password = cls.hash_password(password, salt)
            
            if hashed_password == cls.user_database[username]:
                if username == 'admin':
                    return "REDIRECT:/admin_page"
                return "Login successful"
        
        return "Invalid credentials"
    
    @staticmethod
    def generate_salt():
        """Generate a random salt for password hashing"""
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    @staticmethod
    def hash_password(password, salt):
        """Hash password with salt using SHA-256"""
        salt_bytes = base64.b64decode(salt)
        password_bytes = password.encode('utf-8')
        hash_obj = hashlib.sha256(salt_bytes + password_bytes)
        return base64.b64encode(hash_obj.digest()).decode('utf-8')


# Initialize the class
Lse54.initialize()

if __name__ == "__main__":
    print("Test Case 1 - GET login form:")
    print(Lse54.login()[:50] + "...\\n")
    
    print("Test Case 2 - Valid admin login:")
    print(Lse54.do_login("admin", "admin123") + "\\n")
    
    print("Test Case 3 - Invalid password:")
    print(Lse54.do_login("admin", "wrongpass") + "\\n")
    
    print("Test Case 4 - Non-existent user:")
    print(Lse54.do_login("user123", "password") + "\\n")
    
    print("Test Case 5 - Empty credentials:")
    print(Lse54.do_login("", "") + "\\n")
