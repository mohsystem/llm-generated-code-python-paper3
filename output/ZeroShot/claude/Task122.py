
import hashlib
import base64
import secrets

user_database = {}

class UserCredentials:
    def __init__(self, salt, hashed_password):
        self.salt = salt
        self.hashed_password = hashed_password

def generate_salt():
    return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')

def hash_password(password, salt):
    salt_bytes = base64.b64decode(salt)
    password_bytes = password.encode('utf-8')
    hasher = hashlib.sha256()
    hasher.update(salt_bytes + password_bytes)
    return base64.b64encode(hasher.digest()).decode('utf-8')

def signup(username, password):
    if not username or not username.strip() or not password or len(password) < 8:
        return False
    
    if username in user_database:
        return False
    
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    user_database[username] = UserCredentials(salt, hashed_password)
    return True

def verify_login(username, password):
    if username not in user_database:
        return False
    
    creds = user_database[username]
    hashed_attempt = hash_password(password, creds.salt)
    return hashed_attempt == creds.hashed_password

if __name__ == "__main__":
    print("Test Case 1: Valid signup")
    result1 = signup("user1", "SecurePass123")
    print(f"Signup successful: {result1}")
    print(f"Login verification: {verify_login('user1', 'SecurePass123')}")
    print()
    
    print("Test Case 2: Duplicate username")
    result2 = signup("user1", "AnotherPass456")
    print(f"Signup successful: {result2}")
    print()
    
    print("Test Case 3: Weak password (too short)")
    result3 = signup("user2", "short")
    print(f"Signup successful: {result3}")
    print()
    
    print("Test Case 4: Multiple valid users")
    result4a = signup("alice", "AlicePass2024")
    result4b = signup("bob", "BobSecure789")
    print(f"Alice signup: {result4a}, Bob signup: {result4b}")
    print(f"Alice login: {verify_login('alice', 'AlicePass2024')}")
    print(f"Bob login: {verify_login('bob', 'BobSecure789')}")
    print()
    
    print("Test Case 5: Invalid login attempt")
    signup("user3", "ValidPassword123")
    valid_login = verify_login("user3", "ValidPassword123")
    invalid_login = verify_login("user3", "WrongPassword")
    print(f"Valid login: {valid_login}")
    print(f"Invalid login: {invalid_login}")
