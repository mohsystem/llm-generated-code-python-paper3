
import sqlite3
import re
from typing import Optional, Dict

class Task37:
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format"""
        if not username or len(username.strip()) == 0:
            return False
        if len(username) > 50:
            return False
        # Allow alphanumeric and underscore only
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False
        return True
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Retrieve user information using parameterized query"""
        # Input validation
        if not self.validate_username(username):
            print("Invalid username provided")
            return None
        
        conn = None
        cursor = None
        user_info = None
        
        try:
            # Connect to database with secure settings
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            query = "SELECT user_id, username, email, created_at FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            
            row = cursor.fetchone()
            if row:
                user_info = {
                    'user_id': row['user_id'],
                    'username': row['username'],
                    'email': row['email'],
                    'created_at': row['created_at']
                }
        
        except sqlite3.Error as e:
            # Log error without exposing sensitive information
            print("Database error occurred")
            print(f"Error: {e}")
        
        finally:
            # Close resources properly
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        
        return user_info

def main():
    """Main function with test cases"""
    # Create test database
    db = Task37("test_users.db")
    
    # Setup test data
    try:
        conn = sqlite3.connect("test_users.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users\n                         (user_id INTEGER PRIMARY KEY, username TEXT UNIQUE, \n                          email TEXT, created_at TEXT)''')
        
        test_data = [
            (1, 'john_doe', 'john@example.com', '2024-01-01'),
            (2, 'alice', 'alice@example.com', '2024-01-02'),
            (3, 'bob123', 'bob@example.com', '2024-01-03')
        ]
        cursor.executemany('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?)', test_data)
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Setup error: {e}")
    
    # Test cases
    test_users = ['john_doe', 'alice', 'bob123', 'admin', 'test_user']
    
    print("Testing User Retrieval:\\n")
    for username in test_users:
        print(f"Searching for user: {username}")
        user = db.get_user_by_username(username)
        if user:
            print(f"Found: {user}")
        else:
            print("User not found or error occurred")
        print("---")

if __name__ == "__main__":
    main()
