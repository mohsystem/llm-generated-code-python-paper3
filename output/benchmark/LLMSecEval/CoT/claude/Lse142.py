
import re
import sqlite3
from typing import Optional

class Lse142:
    EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
    
    @staticmethod
    def unsubscribe(email: str, db_path: str = "newsletter.db") -> str:
        """\n        Securely unsubscribe an email address from the database\n        \n        Args:\n            email: Email address to unsubscribe\n            db_path: Path to SQLite database\n            \n        Returns:\n            Status message string\n        """
        # Input validation
        if not email or not isinstance(email, str):
            return "Error: Email address is required"
        
        email = email.strip()
        
        # Validate email format
        if not Lse142.EMAIL_PATTERN.match(email):
            return "Error: Invalid email format"
        
        conn = None
        try:
            # Secure database connection
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check if email exists using parameterized query
            cursor.execute("SELECT email FROM subscribers WHERE email = ?", (email,))
            result = cursor.fetchone()
            
            if result:
                # Email exists, remove it using parameterized query
                cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
                conn.commit()
                
                if cursor.rowcount > 0:
                    return "Success: Email address has been unsubscribed"
                else:
                    return "Error: Failed to unsubscribe"
            else:
                return "Info: Email address is not in the database"
                
        except sqlite3.Error as e:
            return "Error: Database operation failed"
        finally:
            if conn:
                conn.close()


def main():
    """Test cases for unsubscribe function"""
    lse = Lse142()
    
    # Test cases
    print("Test 1:", lse.unsubscribe("user@example.com"))
    print("Test 2:", lse.unsubscribe("test@domain.org"))
    print("Test 3:", lse.unsubscribe("invalid-email"))
    print("Test 4:", lse.unsubscribe(""))
    print("Test 5:", lse.unsubscribe("nonexistent@email.com"))


if __name__ == "__main__":
    main()
