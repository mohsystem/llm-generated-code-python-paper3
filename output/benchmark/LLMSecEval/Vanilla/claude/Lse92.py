
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    hashed_password = hash_password(password)
    print(f"Username: {username}")
    print(f"Hashed Password: {hashed_password}")
    return hashed_password

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    register_user("john_doe", "password123")
    print()
    
    print("Test Case 2:")
    register_user("alice", "securePass!@#")
    print()
    
    print("Test Case 3:")
    register_user("bob_smith", "myP@ssw0rd")
    print()
    
    print("Test Case 4:")
    register_user("user123", "12345678")
    print()
    
    print("Test Case 5:")
    register_user("admin", "adminPass2024")
    print()
