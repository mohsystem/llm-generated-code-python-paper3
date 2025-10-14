
import hashlib
import secrets
import base64
import sqlite3
from typing import Optional

SALT_LENGTH = 16
ITERATIONS = 210000
KEY_LENGTH = 32

def hash_password(password: str, salt: bytes) -> str:
    if not password or len(password) == 0:
        raise ValueError("Password cannot be empty")
    if not salt or len(salt) != SALT_LENGTH:
        raise ValueError("Invalid salt")
    
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=KEY_LENGTH)
    combined = salt + key
    return base64.b64encode(combined).decode('utf-8')

def update_user_password(username: str, new_password: str, conn: sqlite3.Connection) -> bool:
    if not username or len(username) == 0 or len(username) > 255:
        raise ValueError("Invalid username")
    if not new_password or len(new_password) < 8 or len(new_password) > 128:
        raise ValueError("Password must be between 8 and 128 characters")
    
    try:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if cursor.fetchone()[0] == 0:
            return False
        
        salt = secrets.token_bytes(SALT_LENGTH)
        hashed_password = hash_password(new_password, salt)
        
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hashed_password, username))
        conn.commit()
        
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Error updating password: {e}")
        conn.rollback()
        return False

def main():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    cursor.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT)")
    cursor.execute("INSERT INTO users (username, password_hash) VALUES ('user1', 'old_hash')")
    cursor.execute("INSERT INTO users (username, password_hash) VALUES ('user2', 'old_hash')")
    cursor.execute("INSERT INTO users (username, password_hash) VALUES ('user3', 'old_hash')")
    cursor.execute("INSERT INTO users (username, password_hash) VALUES ('user4', 'old_hash')")
    cursor.execute("INSERT INTO users (username, password_hash) VALUES ('user5', 'old_hash')")
    conn.commit()
    
    print(f"Test 1: {update_user_password('user1', 'NewPass123!', conn)}")
    print(f"Test 2: {update_user_password('user2', 'SecureP@ssw0rd', conn)}")
    print(f"Test 3: {update_user_password('user3', 'Str0ng!Pass', conn)}")
    print(f"Test 4: {update_user_password('nonexistent', 'Password123', conn)}")
    print(f"Test 5: {update_user_password('user5', 'MyS3cur3P@ss', conn)}")
    
    conn.close()

if __name__ == "__main__":
    main()
