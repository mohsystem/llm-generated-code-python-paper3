
import sqlite3
import hashlib
import secrets
import base64

def hash_password(password):
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.sha256(salt + password.encode()).digest()
    combined = salt + pwd_hash
    return base64.b64encode(combined).decode('utf-8')

def insert_user(username, password):
    if not username or not username.strip() or not password or not password.strip():
        return False
    
    hashed_password = hash_password(password)
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users\n                         (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                          username TEXT UNIQUE NOT NULL,\n                          password TEXT NOT NULL)''')
        
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, hashed_password))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

if __name__ == "__main__":
    print("Test Case 1:", insert_user("alice", "password123"))
    print("Test Case 2:", insert_user("bob", "SecureP@ss456"))
    print("Test Case 3:", insert_user("charlie", "Test!ng789"))
    print("Test Case 4:", insert_user("", "password"))
    print("Test Case 5:", insert_user("david", "MyP@ssw0rd"))
