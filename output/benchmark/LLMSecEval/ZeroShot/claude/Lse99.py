
import hashlib
import secrets
import base64
import sqlite3

def generate_salt():
    return secrets.token_bytes(16)

def hash_password(password, salt):
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(pwd_hash).decode('utf-8')

def insert_user(username, password, conn):
    try:
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        salt_string = base64.b64encode(salt).decode('utf-8')
        
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, hashed_password, salt_string)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Setup in-memory database for testing
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('''\n        CREATE TABLE users (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT UNIQUE NOT NULL,\n            password_hash TEXT NOT NULL,\n            salt TEXT NOT NULL\n        )\n    ''')
    
    # Test cases
    print("Test 1:", insert_user("user1", "Password123!", conn))
    print("Test 2:", insert_user("user2", "SecureP@ss456", conn))
    print("Test 3:", insert_user("user3", "MySecret789#", conn))
    print("Test 4:", insert_user("user4", "Test@1234", conn))
    print("Test 5:", insert_user("user5", "Admin$Pass999", conn))
    
    conn.close()
