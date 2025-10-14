
import sqlite3
from typing import Optional

class Task37:
    DB_PATH = "users.db"
    
    @staticmethod
    def get_user_info(username: str) -> str:
        """\n        Retrieve user information securely using parameterized queries\n        """
        if not username or not username.strip():
            return "Invalid username"
        
        result = []
        query = "SELECT id, username, email, created_date FROM users WHERE username = ?"
        
        try:
            conn = sqlite3.connect(Task37.DB_PATH)
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            
            if row:
                result.append(f"User ID: {row[0]}")
                result.append(f"Username: {row[1]}")
                result.append(f"Email: {row[2]}")
                result.append(f"Created Date: {row[3]}")
            else:
                result.append("User not found")
                
        except sqlite3.Error as e:
            result.append(f"Database error: {str(e)}")
        finally:
            if conn:
                conn.close()
        
        return "\\n".join(result)
    
    @staticmethod
    def initialize_database():
        """Initialize database with test data"""
        create_table_sql = """\n        CREATE TABLE IF NOT EXISTS users (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT NOT NULL UNIQUE,\n            email TEXT NOT NULL,\n            created_date TEXT NOT NULL\n        )\n        """
        
        insert_sql = "INSERT OR IGNORE INTO users (username, email, created_date) VALUES (?, ?, ?)"
        
        test_data = [
            ("john_doe", "john@example.com", "2024-01-15"),
            ("jane_smith", "jane@example.com", "2024-02-20"),
            ("bob_wilson", "bob@example.com", "2024-03-10"),
            ("alice_jones", "alice@example.com", "2024-04-05"),
            ("charlie_brown", "charlie@example.com", "2024-05-12")
        ]
        
        try:
            conn = sqlite3.connect(Task37.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute(create_table_sql)
            
            for data in test_data:
                cursor.execute(insert_sql, data)
            
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database initialization error: {str(e)}")
        finally:
            if conn:
                conn.close()


def main():
    # Initialize database with test data
    Task37.initialize_database()
    
    print("=== Secure Database Query - Test Cases ===\\n")
    
    # Test Case 1: Valid username
    print("Test Case 1: Valid username 'john_doe'")
    print(Task37.get_user_info("john_doe"))
    print("\\n" + "=" * 50 + "\\n")
    
    # Test Case 2: Another valid username
    print("Test Case 2: Valid username 'jane_smith'")
    print(Task37.get_user_info("jane_smith"))
    print("\\n" + "=" * 50 + "\\n")
    
    # Test Case 3: Non-existent username
    print("Test Case 3: Non-existent username 'unknown_user'")
    print(Task37.get_user_info("unknown_user"))
    print("\\n" + "=" * 50 + "\\n")
    
    # Test Case 4: SQL injection attempt (secured by parameterized query)
    print("Test Case 4: SQL injection attempt")
    print(Task37.get_user_info("' OR '1'='1"))
    print("\\n" + "=" * 50 + "\\n")
    
    # Test Case 5: Empty username
    print("Test Case 5: Empty username")
    print(Task37.get_user_info(""))
    print("\\n" + "=" * 50 + "\\n")


if __name__ == "__main__":
    main()
