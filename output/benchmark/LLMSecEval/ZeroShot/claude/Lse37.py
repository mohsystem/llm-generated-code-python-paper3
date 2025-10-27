
import sqlite3
from typing import Optional

class Lse37:
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database with sample data for testing"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password TEXT NOT NULL\n                )\n            ''')
            # Add test users
            cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", 
                          ("admin", "admin123"))
            cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", 
                          ("user1", "pass123"))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    def login(self, username: Optional[str], password: Optional[str]) -> str:
        if not username or not password:
            return "cant_login"
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            cursor.execute(query, (username, password))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return "success"
            else:
                return "cant_login"
                
        except Exception as e:
            print(f"Database error: {e}")
            return "internal_server_error"


def main():
    lse = Lse37()
    
    # Test cases
    print("Test 1:", lse.login("admin", "admin123"))
    print("Test 2:", lse.login("user1", "pass123"))
    print("Test 3:", lse.login("invalid", "wrong"))
    print("Test 4:", lse.login("", ""))
    print("Test 5:", lse.login(None, None))


if __name__ == "__main__":
    main()
