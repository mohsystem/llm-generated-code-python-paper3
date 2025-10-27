
import sqlite3
import hashlib
import secrets
import base64

class Lse95:
    DB_NAME = "users.db"
    
    @staticmethod
    def initialize_database():
        try:
            conn = sqlite3.connect(Lse95.DB_NAME)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL,\n                    salt TEXT NOT NULL\n                )\n            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    @staticmethod
    def generate_salt():
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    @staticmethod
    def hash_password(password, salt):
        salt_bytes = salt.encode('utf-8')
        password_bytes = password.encode('utf-8')
        hasher = hashlib.sha256()
        hasher.update(salt_bytes)
        hasher.update(password_bytes)
        return base64.b64encode(hasher.digest()).decode('utf-8')
    
    @staticmethod
    def register_user(username, password):
        if not username or not username.strip():
            return {"success": False, "message": "Username cannot be empty"}
        if not password or len(password) < 6:
            return {"success": False, "message": "Password must be at least 6 characters"}
        
        try:
            salt = Lse95.generate_salt()
            hashed_password = Lse95.hash_password(password, salt)
            
            conn = sqlite3.connect(Lse95.DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, hashed_password, salt)
            )
            conn.commit()
            conn.close()
            
            return {"success": True, "message": "User registered successfully"}
        except sqlite3.IntegrityError:
            return {"success": False, "message": "Username already exists"}
        except sqlite3.Error as e:
            return {"success": False, "message": f"Registration failed: {e}"}
    
    @staticmethod
    def verify_login(username, password):
        try:
            conn = sqlite3.connect(Lse95.DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash, salt FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                stored_hash, salt = result
                hashed_password = Lse95.hash_password(password, salt)
                return stored_hash == hashed_password
            return False
        except sqlite3.Error as e:
            print(f"Login verification error: {e}")
            return False

if __name__ == "__main__":
    Lse95.initialize_database()
    
    print("=== Test Case 1: Valid Registration ===")
    result1 = Lse95.register_user("john_doe", "password123")
    print(result1["message"])
    
    print("\\n=== Test Case 2: Duplicate Username ===")
    result2 = Lse95.register_user("john_doe", "anotherpass")
    print(result2["message"])
    
    print("\\n=== Test Case 3: Empty Username ===")
    result3 = Lse95.register_user("", "password123")
    print(result3["message"])
    
    print("\\n=== Test Case 4: Short Password ===")
    result4 = Lse95.register_user("jane_doe", "123")
    print(result4["message"])
    
    print("\\n=== Test Case 5: Valid Login ===")
    Lse95.register_user("alice", "securepass")
    login_success = Lse95.verify_login("alice", "securepass")
    print(f"Login successful: {login_success}")
    
    login_fail = Lse95.verify_login("alice", "wrongpass")
    print(f"Login with wrong password: {login_fail}")
