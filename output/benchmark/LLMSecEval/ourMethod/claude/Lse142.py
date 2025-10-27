
import re
import sqlite3
from typing import Optional

# Email validation pattern - RFC 5322 simplified
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$')
MAX_EMAIL_LENGTH = 254  # RFC 5321


def unsubscribe(email: Optional[str], db_path: str) -> str:
    """\n    Unsubscribes an email address from the database.\n    Uses parameterized queries to prevent SQL injection.\n    Validates input before processing.\n    \n    Args:\n        email: The email address to unsubscribe\n        db_path: Path to the SQLite database file\n        \n    Returns:\n        Status message indicating success or failure\n    """
    # Input validation: null/empty check
    if email is None or not email.strip():
        return "Invalid email address provided."
    
    email = email.strip()
    
    # Input validation: length check to prevent resource exhaustion
    if len(email) > MAX_EMAIL_LENGTH:
        return "Invalid email address provided."
    
    # Input validation: format check using regex
    if not EMAIL_PATTERN.match(email):
        return "Invalid email address provided."
    
    conn = None
    try:
        # Connect to database
        # In production, enable TLS for remote databases and use connection pooling
        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.isolation_level = 'DEFERRED'  # Transaction control
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        check_query = "SELECT COUNT(*) FROM subscribers WHERE email = ?"
        cursor.execute(check_query, (email,))  # Parameterized to prevent SQL injection
        
        count = cursor.fetchone()[0]
        
        if count == 0:
            conn.rollback()
            return "Email address not found in database."
        
        # Email exists, proceed with deletion using parameterized query
        delete_query = "DELETE FROM subscribers WHERE email = ?"
        cursor.execute(delete_query, (email,))  # Parameterized to prevent SQL injection
        
        rows_affected = cursor.rowcount
        
        if rows_affected > 0:
            conn.commit()
            return "Successfully unsubscribed."
        else:
            conn.rollback()
            return "Unsubscribe operation failed."
            
    except sqlite3.Error as e:
        # Rollback on error
        if conn:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass  # Ignore rollback errors
        # Generic error message - don't leak internal details\n        return "An error occurred while processing your request."\n    finally:\n        # Clean up resources\n        if conn:\n            try:\n                conn.close()\n            except sqlite3.Error:\n                pass  # Ignore close errors\n\n\ndef main():\n    """Test the unsubscribe function with various inputs."""\n    # Create in-memory test database\n    db_path = ":memory:"\n    \n    try:\n        conn = sqlite3.connect(db_path)\n        cursor = conn.cursor()\n        \n        # Create test table and insert test data\n        cursor.execute("CREATE TABLE subscribers (email VARCHAR(254) PRIMARY KEY)")\n        cursor.execute("INSERT INTO subscribers (email) VALUES ('test1@example.com')")\n        cursor.execute("INSERT INTO subscribers (email) VALUES ('test2@example.com')")\n        cursor.execute("INSERT INTO subscribers (email) VALUES ('valid@domain.org')")\n        conn.commit()\n        conn.close()\n        \n        # Test case 1: Valid email that exists in database\n        print("Test 1:", unsubscribe("test1@example.com", db_path))\n        \n        # Test case 2: Valid email that does not exist in database\n        print("Test 2:", unsubscribe("notfound@example.com", db_path))\n        \n        # Test case 3: Invalid email format\n        print("Test 3:", unsubscribe("invalid-email", db_path))\n        \n        # Test case 4: None input\n        print("Test 4:", unsubscribe(None, db_path))\n        \n        # Test case 5: SQL injection attempt (should be safely handled)\n        print("Test 5:", unsubscribe("test@test.com' OR '1'='1", db_path))\n        \n    except sqlite3.Error as e:\n        print("Test setup failed")\n\n\nif __name__ == "__main__":
    main()
