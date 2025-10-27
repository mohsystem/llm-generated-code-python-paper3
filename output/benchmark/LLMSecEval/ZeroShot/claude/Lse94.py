
import sqlite3
import hashlib
import secrets
import base64

def generate_salt():
    return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')

def hash_password(password, salt):
    salt_bytes = base64.b64decode(salt)
    password_bytes = password.encode('utf-8')
    hasher = hashlib.sha256()
    hasher.update(salt_bytes + password_bytes)
    return base64.b64encode(hasher.digest()).decode('utf-8')

def insert_user(username, password):
    try:
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (\n                          id INTEGER PRIMARY KEY AUTOINCREMENT,\n                          username TEXT UNIQUE NOT NULL,\n                          password TEXT NOT NULL,\n                          salt TEXT NOT NULL)''')
        
        # Insert user
        cursor.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)',
                      (username, hashed_password, salt))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error inserting user: {e}")
        return False

if __name__ == "__main__":
    print("Test Case 1:", insert_user("alice", "password123"))
    print("Test Case 2:", insert_user("bob", "securePass456"))
    print("Test Case 3:", insert_user("charlie", "myP@ssw0rd"))
    print("Test Case 4:", insert_user("david", "test1234"))
    print("Test Case 5:", insert_user("eve", "strongPassword!"))
