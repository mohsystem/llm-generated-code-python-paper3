
import hashlib
import secrets
import base64
import sqlite3

class Lse95:
    def __init__(self, db_name="users.db"):
        self.db_name = db_name
        self.setup_database()
    
    def setup_database(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT UNIQUE NOT NULL,\n                password TEXT NOT NULL\n            )\n        ''')
        conn.commit()
        conn.close()
    
    def generate_salt(self):
        salt = secrets.token_bytes(16)
        return base64.b64encode(salt).decode('utf-8')
    
    def hash_password(self, password, salt):
        salt_bytes = salt.encode('utf-8')
        password_bytes = password.encode('utf-8')
        hash_obj = hashlib.sha256(salt_bytes + password_bytes)
        return base64.b64encode(hash_obj.digest()).decode('utf-8')
    
    def register_user(self, username, password):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            salt = self.generate_salt()
            hashed_password = self.hash_password(password, salt)
            stored_password = f"{hashed_password}:{salt}"
            
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                          (username, stored_password))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def verify_user(self, username, password):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            
            if result:
                stored_password = result[0]
                parts = stored_password.split(":")
                stored_hash = parts[0]
                salt = parts[1]
                
                hashed_password = self.hash_password(password, salt)
                
                conn.close()
                return hashed_password == stored_hash
            
            conn.close()
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

def main():
    auth_system = Lse95()
    
    print("Test Case 1: Register user1")
    print(auth_system.register_user("user1", "password123"))
    
    print("\\nTest Case 2: Register user2")
    print(auth_system.register_user("user2", "securePass456"))
    
    print("\\nTest Case 3: Verify user1 with correct password")
    print(auth_system.verify_user("user1", "password123"))
    
    print("\\nTest Case 4: Verify user1 with incorrect password")
    print(auth_system.verify_user("user1", "wrongpassword"))
    
    print("\\nTest Case 5: Verify non-existent user")
    print(auth_system.verify_user("user3", "password789"))

if __name__ == "__main__":
    main()
