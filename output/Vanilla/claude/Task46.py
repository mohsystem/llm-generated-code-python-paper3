
import sqlite3
import hashlib
import os

class Task46:
    DB_NAME = "users.db"
    
    def __init__(self):
        self.initialize_database()
    
    def initialize_database(self):
        conn = sqlite3.connect(self.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                name TEXT NOT NULL,\n                email TEXT UNIQUE NOT NULL,\n                password TEXT NOT NULL\n            )\n        ''')
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, name, email, password):
        try:
            hashed_password = self.hash_password(password)
            conn = sqlite3.connect(self.DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, hashed_password)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError as e:
            print(f"Registration error: {e}")
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def user_exists(self, email):
        try:
            conn = sqlite3.connect(self.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except Exception:
            return False


def main():
    print("User Registration System - Test Cases\\n")
    system = Task46()
    
    # Test Case 1
    print("Test Case 1: Register new user")
    result1 = system.register_user("John Doe", "john@example.com", "password123")
    print(f"Registration successful: {result1}")
    print(f"User exists: {system.user_exists('john@example.com')}")
    print()
    
    # Test Case 2
    print("Test Case 2: Register another user")
    result2 = system.register_user("Jane Smith", "jane@example.com", "securePass456")
    print(f"Registration successful: {result2}")
    print(f"User exists: {system.user_exists('jane@example.com')}")
    print()
    
    # Test Case 3
    print("Test Case 3: Try to register duplicate email")
    result3 = system.register_user("John Another", "john@example.com", "newpassword")
    print(f"Registration successful: {result3}")
    print()
    
    # Test Case 4
    print("Test Case 4: Register user with special characters")
    result4 = system.register_user("Mike O'Brien", "mike.obrien@example.com", "P@ssw0rd!")
    print(f"Registration successful: {result4}")
    print(f"User exists: {system.user_exists('mike.obrien@example.com')}")
    print()
    
    # Test Case 5
    print("Test Case 5: Register user with long name")
    result5 = system.register_user("Alexander Christopher Wellington", "alex@example.com", "myPassword789")
    print(f"Registration successful: {result5}")
    print(f"User exists: {system.user_exists('alex@example.com')}")


if __name__ == "__main__":
    main()
