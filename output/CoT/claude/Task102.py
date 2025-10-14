
import hashlib
import secrets
import base64
import sqlite3

def hash_password(password):
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    combined = salt + pwd_hash
    return base64.b64encode(combined).decode('utf-8')

def update_user_password(username, new_password):
    if not username or not isinstance(username, str) or not username.strip():
        return False
    
    if not new_password or not isinstance(new_password, str) or not new_password.strip():
        return False
    
    if len(username) > 255 or len(new_password) > 255:
        return False
    
    hashed_password = hash_password(new_password)
    
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", 
                      (hashed_password, username))
        
        conn.commit()
        rows_affected = cursor.rowcount
        conn.close()
        
        return rows_affected > 0
        
    except Exception as e:
        print("Error updating password")
        return False

if __name__ == "__main__":
    print("Test Case 1:", update_user_password("user1", "SecurePass123!"))
    print("Test Case 2:", update_user_password("user2", "AnotherP@ssw0rd"))
    print("Test Case 3:", update_user_password("admin", "AdminSecure#456"))
    print("Test Case 4:", update_user_password("", "password"))
    print("Test Case 5:", update_user_password("user3", ""))
