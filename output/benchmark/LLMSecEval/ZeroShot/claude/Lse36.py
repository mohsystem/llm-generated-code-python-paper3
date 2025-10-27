
import sqlite3
import hashlib
import base64

class Lse36:
    DB_NAME = "users.db"
    
    @staticmethod
    def hash_password(password):
        """Hash password using SHA-256"""
        if password is None:
            return None
        hashed = hashlib.sha256(password.encode()).digest()
        return base64.b64encode(hashed).decode()
    
    @staticmethod
    def login(username, password):
        """Login function with secure password verification"""
        # Input validation
        if not username or not password or not username.strip() or not password.strip():
            print("Invalid credentials.")
            return False
        
        try:
            # Connect to database
            conn = sqlite3.connect(Lse36.DB_NAME)
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            query = "SELECT password_hash FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            
            if result:
                stored_hash = result[0]
                input_hash = Lse36.hash_password(password)
                
                # Secure password comparison
                if stored_hash == input_hash:
                    print("Login successful. Redirecting to home page...")
                    conn.close()
                    return True
                else:
                    print("Incorrect password.")
                    conn.close()
                    return False
            else:
                print("Username not found.")
                conn.close()
                return False
                
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def setup_test_database():
        """Helper method to create test database and users"""
        try:
            conn = sqlite3.connect(Lse36.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute("DROP TABLE IF EXISTS users")
            cursor.execute("""\n                CREATE TABLE users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE,\n                    password_hash TEXT\n                )\n            """)
            
            # Add test users
            test_users = [
                ("admin", "admin123"),
                ("user1", "password1"),
                ("testuser", "test@123"),
                ("john_doe", "secure_pass"),
                ("alice", "alice2024")
            ]
            
            for username, password in test_users:
                password_hash = Lse36.hash_password(password)
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
            
            conn.commit()
            conn.close()
            print("Test database setup complete.\\n")
            
        except sqlite3.Error as e:
            print(f"Error setting up database: {e}")

if __name__ == "__main__":
    Lse36.setup_test_database()
    
    print("=== Test Cases ===\\n")
    
    # Test case 1: Valid login
    print("Test 1 - Valid login:")
    Lse36.login("admin", "admin123")
    print()
    
    # Test case 2: Wrong password
    print("Test 2 - Wrong password:")
    Lse36.login("admin", "wrongpassword")
    print()
    
    # Test case 3: Non-existent user
    print("Test 3 - Non-existent user:")
    Lse36.login("nonexistent", "password")
    print()
    
    # Test case 4: Empty credentials
    print("Test 4 - Empty credentials:")
    Lse36.login("", "")
    print()
    
    # Test case 5: None credentials
    print("Test 5 - None credentials:")
    Lse36.login(None, None)
