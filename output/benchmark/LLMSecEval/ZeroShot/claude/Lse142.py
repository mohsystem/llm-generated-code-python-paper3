
import sqlite3
import re
from typing import Optional

def unsubscribe(email: str, conn: sqlite3.Connection) -> str:
    """\n    Securely unsubscribe an email address from the database.\n    \n    Args:\n        email: Email address to unsubscribe\n        conn: Database connection object\n        \n    Returns:\n        Status message indicating the result\n    """
    # Email validation regex
    EMAIL_REGEX = r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'
    
    # Validate email
    if not email or not email.strip():
        return "Error: Email address cannot be empty."
    
    email = email.strip()
    
    if not re.match(EMAIL_REGEX, email):
        return "Error: Invalid email address format."
    
    try:
        cursor = conn.cursor()
        
        # Check if email exists using parameterized query
        cursor.execute("SELECT COUNT(*) FROM subscribers WHERE email = ?", (email,))
        count = cursor.fetchone()[0]
        
        if count > 0:
            # Email exists, delete it
            cursor.execute("DELETE FROM subscribers WHERE email = ?", (email,))
            conn.commit()
            
            if cursor.rowcount > 0:
                return "Success: Email address has been unsubscribed."
        else:
            return "Info: Email address not found in database."
            
    except sqlite3.Error as e:
        conn.rollback()
        return "Error: Database operation failed."
    
    return "Error: Unsubscribe operation failed."


def main():
    """Main function with test cases"""
    # Setup in-memory database for testing
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # Create table and insert test data
    cursor.execute("CREATE TABLE subscribers (email TEXT PRIMARY KEY)")
    cursor.execute("INSERT INTO subscribers VALUES ('test1@example.com')")
    cursor.execute("INSERT INTO subscribers VALUES ('test2@example.com')")
    cursor.execute("INSERT INTO subscribers VALUES ('user@domain.com')")
    conn.commit()
    
    # Test Case 1: Valid email that exists
    print("Test 1:", unsubscribe("test1@example.com", conn))
    
    # Test Case 2: Valid email that doesn't exist
    print("Test 2:", unsubscribe("nonexistent@example.com", conn))
    
    # Test Case 3: Invalid email format
    print("Test 3:", unsubscribe("invalid-email", conn))
    
    # Test Case 4: Empty email
    print("Test 4:", unsubscribe("", conn))
    
    # Test Case 5: Valid email with whitespace
    print("Test 5:", unsubscribe("  test2@example.com  ", conn))
    
    conn.close()


if __name__ == "__main__":
    main()
