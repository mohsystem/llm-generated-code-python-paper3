
import sqlite3

def unsubscribe_email(email, db_connection=None):
    try:
        # Use provided connection or create a mock one
        if db_connection is None:
            # For testing, create an in-memory database
            conn = sqlite3.connect(':memory:')
            cursor = conn.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS subscribers (email TEXT)')
            cursor.execute('INSERT INTO subscribers VALUES (?)', ('user1@example.com',))
            cursor.execute('INSERT INTO subscribers VALUES (?)', ('user2@example.com',))
            conn.commit()
        else:
            conn = db_connection
            
        cursor = conn.cursor()
        
        # Check if email exists in database
        cursor.execute("SELECT COUNT(*) FROM subscribers WHERE email = ?", (email,))
        result = cursor.fetchone()
        
        if result[0] > 0:
            # Email exists, call unsubscribe script
            script_result = call_unsubscribe_script(email)
            
            if script_result == 0:
                return 1  # Success
            else:
                return 0  # Script failed
        else:
            # Email doesn't exist\n            return 0\n            \n    except Exception as e:\n        print(f"Error: {e}")\n        return 0\n\ndef call_unsubscribe_script(email):\n    # Simulate calling an unsubscribe script\n    # In real scenario, this would execute an external script or perform database update\n    try:\n        # Simulate script execution (returns 0 for success, non-zero for failure)\n        if email and '@' in email:
            return 0  # Success
        return 1  # Failure
    except Exception:
        return 1  # Failure

# Test cases
if __name__ == "__main__":
    print("Test Case 1:", unsubscribe_email("user1@example.com"))
    print("Test Case 2:", unsubscribe_email("user2@example.com"))
    print("Test Case 3:", unsubscribe_email("nonexistent@example.com"))
    print("Test Case 4:", unsubscribe_email("invalid-email"))
    print("Test Case 5:", unsubscribe_email("user5@example.com"))
