
import sqlite3
import hashlib

class Lse38:
    def __init__(self, db_path='users.db'):
        self.db_path = db_path
        self.setup_database()
    
    def setup_database(self):
        """Setup a simple database for testing"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password TEXT NOT NULL\n                )\n            ''')
            # Insert test users
            test_users = [
                ('admin', 'admin123'),
                ('user1', 'pass123'),
                ('testuser', 'testpass')
            ]
            for username, password in test_users:
                try:
                    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                                 (username, password))
                except sqlite3.IntegrityError:
                    pass
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database setup error: {e}")
    
    def authenticate_user(self, username, password):
        """Authenticate user against database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                         (username, password))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return "dashboard"
            else:
                return "login"
        except Exception as e:
            print(f"Authentication error: {e}")
            return "error"

if __name__ == "__main__":
    lse38 = Lse38()
    
    # Test cases
    print("Test Case 1:")
    print("Result:", lse38.authenticate_user("admin", "admin123"))
    
    print("\\nTest Case 2:")
    print("Result:", lse38.authenticate_user("user1", "pass123"))
    
    print("\\nTest Case 3:")
    print("Result:", lse38.authenticate_user("wronguser", "wrongpass"))
    
    print("\\nTest Case 4:")
    print("Result:", lse38.authenticate_user("", ""))
    
    print("\\nTest Case 5:")
    print("Result:", lse38.authenticate_user("testuser", "testpass"))
