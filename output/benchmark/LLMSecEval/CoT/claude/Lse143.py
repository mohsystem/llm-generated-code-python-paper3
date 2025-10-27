
import sqlite3
import re
from typing import Optional

class Lse143:
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with subscribers table"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS subscribers (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    email TEXT UNIQUE NOT NULL\n                )\n            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format"""
        if not email:
            return False
        email_regex = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
        return re.match(email_regex, email) is not None
    
    def unsubscribe_user(self, email: Optional[str]) -> str:
        """Main unsubscribe function"""
        # Input validation
        if email is None or not email.strip():
            return "Invalid email parameter"
        
        # Sanitize email input
        email = email.strip().lower()
        
        # Validate email format
        if not self.is_valid_email(email):
            return "Invalid email format"
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if email exists using parameterized query
            cursor.execute("SELECT COUNT(*) FROM subscribers WHERE email = ?", (email,))
            count = cursor.fetchone()[0]
            
            if count > 0:
                # Email exists, delete it
                cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
                conn.commit()
                
                if cursor.rowcount > 0:
                    result = f"Successfully unsubscribed: {email}"
                else:
                    result = "Failed to unsubscribe"
            else:
                result = f"Email not subscribed: {email}"
            
            conn.close()
            return result
            
        except sqlite3.Error as e:
            return f"Database error: {e}"
    
    def add_subscriber(self, email: str):
        """Helper method to add subscriber for testing"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO subscribers (email) VALUES (?)", 
                          (email.strip().lower(),))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Error adding subscriber: {e}")


def main():
    service = Lse143()
    
    # Test cases
    print("=== Test Case 1: Unsubscribe existing user ===")
    service.add_subscriber("user1@example.com")
    print(service.unsubscribe_user("user1@example.com"))
    
    print("\\n=== Test Case 2: Unsubscribe non-existing user ===")
    print(service.unsubscribe_user("nonexistent@example.com"))
    
    print("\\n=== Test Case 3: Invalid email format ===")
    print(service.unsubscribe_user("invalid-email"))
    
    print("\\n=== Test Case 4: Empty email ===")
    print(service.unsubscribe_user(""))
    
    print("\\n=== Test Case 5: Null email ===")
    print(service.unsubscribe_user(None))


if __name__ == "__main__":
    main()
