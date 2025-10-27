
import sqlite3
import os

class Lse143:
    DB_PATH = "mailing_list.db"
    
    @staticmethod
    def unsubscribe(email):
        if not email or not email.strip():
            return "Invalid email address"
        
        conn = None
        try:
            # Create database connection
            conn = sqlite3.connect(Lse143.DB_PATH)
            cursor = conn.cursor()
            
            # Check if email exists in database
            cursor.execute("SELECT email FROM subscribers WHERE email = ?", (email,))
            result = cursor.fetchone()
            
            if result:
                # Email exists, delete it
                cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
                conn.commit()
                return f"Successfully unsubscribed: {email}"
            else:
                # Email not found
                return f"User is not subscribed: {email}"
                
        except sqlite3.Error as e:
            return f"Error processing unsubscribe request: {str(e)}"
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def initialize_database():
        try:
            conn = sqlite3.connect(Lse143.DB_PATH)
            cursor = conn.cursor()
            
            # Create table if not exists
            cursor.execute("""\n                CREATE TABLE IF NOT EXISTS subscribers (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    email TEXT UNIQUE NOT NULL\n                )\n            """)
            
            # Insert test data
            test_emails = [
                "user1@example.com",
                "user2@example.com",
                "user3@example.com"
            ]
            
            for email in test_emails:
                cursor.execute("INSERT OR IGNORE INTO subscribers (email) VALUES (?)", (email,))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")


if __name__ == "__main__":
    # Initialize database with test data
    Lse143.initialize_database()
    
    # Test case 1: Unsubscribe existing user
    print("Test 1:", Lse143.unsubscribe("user1@example.com"))
    
    # Test case 2: Try to unsubscribe same user again
    print("Test 2:", Lse143.unsubscribe("user1@example.com"))
    
    # Test case 3: Unsubscribe another existing user
    print("Test 3:", Lse143.unsubscribe("user2@example.com"))
    
    # Test case 4: Try to unsubscribe non-existent user
    print("Test 4:", Lse143.unsubscribe("nonexistent@example.com"))
    
    # Test case 5: Try with empty email
    print("Test 5:", Lse143.unsubscribe(""))
