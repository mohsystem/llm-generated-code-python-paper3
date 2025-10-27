
import sqlite3
import hashlib
import secrets
import base64

class Lse91:
    DB_NAME = "users.db"
    
    @staticmethod
    def initialize_database():
        conn = sqlite3.connect(Lse91.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT UNIQUE NOT NULL,\n                password_hash TEXT NOT NULL,\n                salt TEXT NOT NULL\n            )\n        ''')
        conn.commit()
        conn.close()
    
    @staticmethod
    def generate_salt():
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    @staticmethod
    def hash_password(password, salt):
        salt_bytes = base64.b64decode(salt)
        password_bytes = password.encode('utf-8')
        hashed = hashlib.sha256(salt_bytes + password_bytes).digest()
        return base64.b64encode(hashed).decode('utf-8')
    
    @staticmethod
    def register_user(username, password):
        if not username or not username.strip():
            return {"success": False, "message": "Username cannot be empty"}
        if not password or len(password) < 8:
            return {"success": False, "message": "Password must be at least 8 characters"}
        
        salt = Lse91.generate_salt()
        hashed_password = Lse91.hash_password(password, salt)
        
        try:
            conn = sqlite3.connect(Lse91.DB_NAME)
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
        except Exception as e:
            return {"success": False, "message": f"Registration failed: {str(e)}"}

def main():
    Lse91.initialize_database()
    
    # Test case 1: Valid registration
    result1 = Lse91.register_user("john_doe", "SecurePass123")
    print(f"Test 1: {result1['message']}")
    
    # Test case 2: Duplicate username
    result2 = Lse91.register_user("john_doe", "AnotherPass456")
    print(f"Test 2: {result2['message']}")
    
    # Test case 3: Short password
    result3 = Lse91.register_user("jane_doe", "short")
    print(f"Test 3: {result3['message']}")
    
    # Test case 4: Empty username
    result4 = Lse91.register_user("", "ValidPassword123")
    print(f"Test 4: {result4['message']}")
    
    # Test case 5: Valid registration with special characters
    result5 = Lse91.register_user("alice_smith", "P@ssw0rd!2023")
    print(f"Test 5: {result5['message']}")

if __name__ == "__main__":
    main()
