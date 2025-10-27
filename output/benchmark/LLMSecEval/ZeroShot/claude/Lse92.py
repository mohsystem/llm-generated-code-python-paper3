
import hashlib
import base64
import secrets

class RegistrationResult:
    def __init__(self, username, hashed_password, salt):
        self.username = username
        self.hashed_password = hashed_password
        self.salt = salt

def generate_salt():
    return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')

def hash_password(password, salt):
    salt_bytes = base64.b64decode(salt)
    password_bytes = password.encode('utf-8')
    hasher = hashlib.sha256()
    hasher.update(salt_bytes)
    hasher.update(password_bytes)
    return base64.b64encode(hasher.digest()).decode('utf-8')

def register_user(username, password):
    if not username or not username.strip():
        raise ValueError("Username cannot be empty")
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    
    return RegistrationResult(username, hashed_password, salt)

if __name__ == "__main__":
    # Test case 1
    try:
        result1 = register_user("john_doe", "SecurePass123")
        print(f"Test 1 - Username: {result1.username}")
        print(f"Hashed Password: {result1.hashed_password}")
        print(f"Salt: {result1.salt}")
        print()
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2
    try:
        result2 = register_user("alice_smith", "MyP@ssw0rd!")
        print(f"Test 2 - Username: {result2.username}")
        print(f"Hashed Password: {result2.hashed_password}")
        print(f"Salt: {result2.salt}")
        print()
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3 - Empty username
    try:
        result3 = register_user("", "Password123")
        print(f"Test 3 - Username: {result3.username}")
    except Exception as e:
        print(f"Test 3 failed (expected): {e}")
        print()
    
    # Test case 4 - Short password
    try:
        result4 = register_user("bob_jones", "short")
        print(f"Test 4 - Username: {result4.username}")
    except Exception as e:
        print(f"Test 4 failed (expected): {e}")
        print()
    
    # Test case 5
    try:
        result5 = register_user("emma_wilson", "StrongPassword2024")
        print(f"Test 5 - Username: {result5.username}")
        print(f"Hashed Password: {result5.hashed_password}")
        print(f"Salt: {result5.salt}")
    except Exception as e:
        print(f"Test 5 failed: {e}")
