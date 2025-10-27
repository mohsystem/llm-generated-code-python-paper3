
import hashlib
import secrets
import base64
import sqlite3

class Lse93:
    @staticmethod
    def hash_password(password, salt):
        """Hash password with salt using SHA-256"""
        pwd_bytes = password.encode('utf-8')
        hash_obj = hashlib.sha256(salt + pwd_bytes)
        return base64.b64encode(hash_obj.digest()).decode('utf-8')
    
    @staticmethod
    def generate_salt():
        """Generate a random salt"""
        return secrets.token_bytes(16)
    
    @staticmethod
    def insert_user(username, password, conn):
        """Insert user with hashed password into database"""
        try:
            salt = Lse93.generate_salt()
            hashed_password = Lse93.hash_password(password, salt)
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
    # Create in-memory database for testing
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('''\n        CREATE TABLE users (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT UNIQUE,\n            password_hash TEXT,\n            salt TEXT\n        )\n    ''')
    conn.commit()
    
    # Test case 1
    print("Test 1:", Lse93.insert_user("user1", "password123", conn))
    
    # Test case 2
    print("Test 2:", Lse93.insert_user("user2", "securePass456", conn))
    
    # Test case 3
    print("Test 3:", Lse93.insert_user("user3", "myP@ssw0rd", conn))
    
    # Test case 4
    print("Test 4:", Lse93.insert_user("user4", "testPassword789", conn))
    
    # Test case 5
    print("Test 5:", Lse93.insert_user("user5", "anotherSecure#Pass", conn))
    
    conn.close()
