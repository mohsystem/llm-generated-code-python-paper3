
import hashlib
import secrets
import base64

def generate_salt():
    salt = secrets.token_bytes(16)
    return base64.b64encode(salt).decode('utf-8')

def hash_password(password, salt):
    salt_bytes = base64.b64decode(salt)
    password_bytes = password.encode('utf-8')
    hasher = hashlib.sha256()
    hasher.update(salt_bytes)
    hasher.update(password_bytes)
    hashed_password = hasher.digest()
    return base64.b64encode(hashed_password).decode('utf-8')

def register_user(username, password):
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    stored_value = f"{salt}:{hashed_password}"
    # In real application, store stored_value in database for the username
    return stored_value

if __name__ == "__main__":
    # Test case 1
    result1 = register_user("user1", "password123")
    print(f"Test 1 - User: user1, Stored: {result1}")
    
    # Test case 2
    result2 = register_user("alice", "securePass456")
    print(f"Test 2 - User: alice, Stored: {result2}")
    
    # Test case 3
    result3 = register_user("bob", "myP@ssw0rd")
    print(f"Test 3 - User: bob, Stored: {result3}")
    
    # Test case 4
    result4 = register_user("admin", "Admin#2024")
    print(f"Test 4 - User: admin, Stored: {result4}")
    
    # Test case 5
    result5 = register_user("testuser", "Test!ng123")
    print(f"Test 5 - User: testuser, Stored: {result5}")
