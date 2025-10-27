
import hashlib
import secrets
import base64
import sqlite3

class Lse94:
    SALT_LENGTH = 16
    
    @staticmethod
    def generate_salt():
        salt = secrets.token_bytes(Lse94.SALT_LENGTH)
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def hash_password(password, salt):
        salt_bytes = base64.b64decode(salt)
        password_bytes = password.encode('utf-8')
        hasher = hashlib.sha256()
        hasher.update(salt_bytes + password_bytes)
        hashed = hasher.digest()
        return base64.b64encode(hashed).decode('utf-8')
    
    @staticmethod
    def insert_user(username, password):
        if not username or not username.strip() or not password or len(password) < 8:
            return False
        
        salt = Lse94.generate_salt()
        hashed_password = Lse94.hash_password(password, salt)
        combined_hash = f"{salt}:{hashed_password}"
        
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, combined_hash)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error inserting user: {e}")
            return False

if __name__ == "__main__":
    # Test cases
    print(f"Test 1: {Lse94.insert_user('user1', 'password123')}")
    print(f"Test 2: {Lse94.insert_user('user2', 'securePass456')}")
    print(f"Test 3: {Lse94.insert_user('user3', 'myP@ssw0rd')}")
    print(f"Test 4: {Lse94.insert_user('', 'password123')}")
    print(f"Test 5: {Lse94.insert_user('user5', 'short')}")
