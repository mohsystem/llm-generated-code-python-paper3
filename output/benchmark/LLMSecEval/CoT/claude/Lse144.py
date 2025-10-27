
import re
import sqlite3
from typing import Optional

class Lse144:
    EMAIL_REGEX = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
    
    @staticmethod
    def process_unsubscribe(email: Optional[str], conn: sqlite3.Connection) -> int:
        if not email or not email.strip():
            return 0
        
        if not re.match(Lse144.EMAIL_REGEX, email):
            return 0
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
            count = cursor.fetchone()[0]
            cursor.close()
            
            if count > 0:
                script_result = Lse144.unsubscribe_email(email)
                return 1 if script_result == 0 else 0
            return 0
            
        except sqlite3.Error as e:
            print("Database error occurred", file=__import__('sys').stderr)
            return 0
    
    @staticmethod
    def unsubscribe_email(email: str) -> int:
        # Simulated unsubscribe script call
        # In production, use subprocess with controlled parameters
        return 0  # Success
    
    @staticmethod
    def main():
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)")
        cursor.execute("INSERT INTO users (email) VALUES ('test@example.com')")
        conn.commit()
        cursor.close()
        
        print("Test 1:", Lse144.process_unsubscribe("test@example.com", conn))
        print("Test 2:", Lse144.process_unsubscribe("nonexistent@example.com", conn))
        print("Test 3:", Lse144.process_unsubscribe("invalid-email", conn))
        print("Test 4:", Lse144.process_unsubscribe(None, conn))
        print("Test 5:", Lse144.process_unsubscribe("", conn))
        
        conn.close()

if __name__ == "__main__":
    Lse144.main()
