
import re
import sqlite3
from typing import Optional

class Lse144:
    EMAIL_REGEX = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
    
    # Database configuration - should be configured securely
    DB_PATH = 'emaildb.db'
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validates email format"""
        if not email or not isinstance(email, str):
            return False
        return bool(re.match(Lse144.EMAIL_REGEX, email))
    
    @staticmethod
    def call_unsubscribe_script(email: str) -> int:
        """\n        Simulates calling an unsubscribe script\n        Returns 0 on success, non-zero on failure\n        """
        try:
            # In a real implementation, this would call an actual script
            # For security, validate and sanitize input before passing to external script
            
            # Simulate script execution
            # Return 0 for success
            return 0
            
        except Exception as e:
            print(f"Script execution error: {e}")
            return 1
    
    @staticmethod
    def unsubscribe_email(email: str) -> int:
        """\n        Checks if email exists in database and unsubscribes if found\n        Returns 1 if successfully unsubscribed, 0 otherwise\n        """
        # Validate email format first
        if not Lse144.is_valid_email(email):
            return 0
        
        conn = None
        cursor = None
        
        try:
            # Establish database connection
            conn = sqlite3.connect(Lse144.DB_PATH)
            cursor = conn.cursor()
            
            # Check if email exists using parameterized query (prevents SQL injection)
            check_query = "SELECT email FROM subscribers WHERE email = ?"
            cursor.execute(check_query, (email,))
            result = cursor.fetchone()
            
            # If email doesn't exist, return 0
            if not result:
                return 0
            
            # Email exists, call unsubscribe script
            unsubscribe_result = Lse144.call_unsubscribe_script(email)
            
            # If script returns 0 (success), return 1, otherwise return 0
            if unsubscribe_result == 0:
                return 1
            else:
                return 0
                
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return 0
        finally:
            # Clean up resources
            if cursor:
                cursor.close()
            if conn:
                conn.close()


def main():
    """Test cases"""
    print("Test Case 1 (valid existing email):", Lse144.unsubscribe_email("user1@example.com"))
    print("Test Case 2 (valid non-existing email):", Lse144.unsubscribe_email("nonexistent@example.com"))
    print("Test Case 3 (invalid email format):", Lse144.unsubscribe_email("invalid-email"))
    print("Test Case 4 (null email):", Lse144.unsubscribe_email(None))
    print("Test Case 5 (empty email):", Lse144.unsubscribe_email(""))


if __name__ == "__main__":
    main()
