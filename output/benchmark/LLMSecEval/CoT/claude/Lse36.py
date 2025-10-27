
import sqlite3
import hashlib
import secrets
import base64

class Lse36:
    DB_PATH = "userdb.db"
    
    @staticmethod
    def hash_password(password, salt):
        salt_bytes = base64.b64decode(salt)
        password_bytes = password.encode('utf-8')
        hashed = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)
        return base64.b64encode(hashed).decode('utf-8')
    
    @staticmethod
    def generate_salt():
        salt = secrets.token_bytes(16)
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def login(username, password):
        if not username or not password or not username.strip() or not password.strip():
            return "Invalid credentials"
        
        conn = None
        cursor = None
        
        try:
            conn = sqlite3.connect(Lse36.DB_PATH)
            cursor = conn.cursor()
            
            query = "SELECT password_hash, salt FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            
            result = cursor.fetchone()
            
            if result:
                stored_hash, salt = result
                input_hash = Lse36.hash_password(password, salt)
                
                if stored_hash == input_hash:
                    return "Redirect to home page"
                else:
                    return "Incorrect password"
            else:
                return "User not found"
                
        except sqlite3.Error as e:
            return f"Database error: {str(e)}"
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()


if __name__ == "__main__":
    print("Test Case 1: Valid credentials")
    print(Lse36.login("user1", "password123"))
    
    print("\\nTest Case 2: Invalid password")
    print(Lse36.login("user1", "wrongpassword"))
    
    print("\\nTest Case 3: Non-existent user")
    print(Lse36.login("nonexistent", "password123"))
    
    print("\\nTest Case 4: Empty username")
    print(Lse36.login("", "password123"))
    
    print("\\nTest Case 5: Null values")
    print(Lse36.login(None, None))
