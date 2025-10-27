
import sqlite3
import re
from typing import Optional

class Lse143:
    EMAIL_REGEX = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
    DB_PATH = 'mailing_list.db'
    
    @staticmethod
    def unsubscribe(email: str) -> str:
        """\n        Unsubscribe a user from the mailing list\n        \n        Args:\n            email: The email address to unsubscribe\n            \n        Returns:\n            A message indicating the result of the operation\n        """
        # Input validation
        if not email or not isinstance(email, str):
            return "Invalid email parameter"
        
        email = email.strip()
        
        # Validate email format
        if not re.match(Lse143.EMAIL_REGEX, email):
            return "Invalid email format"
        
        conn = None
        try:
            # Connect to database
            conn = sqlite3.connect(Lse143.DB_PATH)
            cursor = conn.cursor()
            
            # Check if email exists
            cursor.execute("SELECT email FROM subscribers WHERE email = ?", (email,))
            result = cursor.fetchone()
            
            if result:
                # Email exists, delete the user
                cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
                conn.commit()
                
                if cursor.rowcount > 0:
                    return f"Successfully unsubscribed: {email}"
                else:
                    return "Failed to unsubscribe"
            else:
                # Email not found
                return "User is not subscribed"
                
        except sqlite3.Error as e:
            return f"Database error: {str(e)}"
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def init_test_database():
        """Initialize database with test data"""
        try:
            conn = sqlite3.connect(Lse143.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""\n                CREATE TABLE IF NOT EXISTS subscribers (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    email TEXT UNIQUE NOT NULL\n                )\n            """)
            
            cursor.execute("DELETE FROM subscribers")
            
            test_emails = [
                'test1@example.com',
                'test2@example.com',
                'user@domain.com'
            ]
            
            for email in test_emails:
                cursor.execute("INSERT INTO subscribers (email) VALUES (?)", (email,))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            print(f"Error initializing database: {e}")

def main():
    # Initialize test database
    Lse143.init_test_database()
    
    # Test case 1: Valid unsubscribe
    print("Test 1:", Lse143.unsubscribe("test1@example.com"))
    
    # Test case 2: User not subscribed
    print("Test 2:", Lse143.unsubscribe("notfound@example.com"))
    
    # Test case 3: Another valid unsubscribe
    print("Test 3:", Lse143.unsubscribe("test2@example.com"))
    
    # Test case 4: Invalid email format
    print("Test 4:", Lse143.unsubscribe("invalid-email"))
    
    # Test case 5: Empty email
    print("Test 5:", Lse143.unsubscribe(""))

if __name__ == "__main__":
    main()
