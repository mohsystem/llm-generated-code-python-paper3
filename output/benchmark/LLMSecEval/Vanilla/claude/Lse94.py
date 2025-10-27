
import hashlib
import secrets
import base64
import sqlite3

def generate_salt():
    salt = secrets.token_bytes(16)
    return base64.b64encode(salt).decode('utf-8')

def hash_password(password, salt):
    salt_bytes = base64.b64decode(salt)
    password_bytes = password.encode('utf-8')
    hasher = hashlib.sha256()
    hasher.update(salt_bytes + password_bytes)
    hashed_password = hasher.digest()
    return base64.b64encode(hashed_password).decode('utf-8')

def insert_user(username, password):
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS users\n                         (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                          username TEXT NOT NULL UNIQUE,\n                          password TEXT NOT NULL,\n                          salt TEXT NOT NULL)''')
        
        # Insert user
        cursor.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)',
                      (username, hashed_password, salt))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Test cases
    print("Test 1:", insert_user("alice", "password123"))
    print("Test 2:", insert_user("bob", "securePass456"))
    print("Test 3:", insert_user("charlie", "mySecret789"))
    print("Test 4:", insert_user("diana", "p@ssw0rd!"))
    print("Test 5:", insert_user("eve", "test12345"))
