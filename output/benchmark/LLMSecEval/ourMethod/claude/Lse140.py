
import psycopg2
from typing import Optional

# Database configuration - should be externalized in production
DB_CONFIG = {
    'host': 'localhost',
    'database': 'mydb',
    'user': 'dbuser',
    'password': 'dbpass',
    'port': 5432
}

def check_username_exists(username: Optional[str]) -> bool:
    """\n    Check if username exists in database using parameterized query to prevent SQL injection\n    \n    Args:\n        username: The username to check (input validation applied)\n    \n    Returns:\n        True if username exists, False otherwise\n    """
    # Input validation: reject None, empty, or excessively long usernames
    if username is None or not isinstance(username, str):
        return False
    
    username = username.strip()
    if not username:
        return False
    
    if len(username) > 255:
        return False  # Reject unreasonably long input
    
    conn = None
    cursor = None
    
    try:
        # Establish database connection with timeout
        conn = psycopg2.connect(
            host=DB_CONFIG['host'],
            database=DB_CONFIG['database'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            port=DB_CONFIG['port'],
            connect_timeout=10
        )
        
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        # The %s placeholder ensures user input is properly escaped by psycopg2
        query = "SELECT 1 FROM users WHERE username = %s LIMIT 1"
        
        # Execute with parameter - psycopg2 handles escaping automatically
        cursor.execute(query, (username,))
        
        # Return True if any row exists
        result = cursor.fetchone()
        return result is not None
        
    except psycopg2.Error as e:
        # Log error securely without exposing internal details
        print("Database error occurred", file=__import__('sys').stderr)
        return False
    except Exception as e:
        # Catch any other unexpected errors
        print("Unexpected error occurred", file=__import__('sys').stderr)
        return False
    finally:
        # Ensure resources are closed to prevent leaks
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    # Test case 1: Valid username that exists
    print(f"Test 1 - Valid username 'john_doe': {check_username_exists('john_doe')}")
    
    # Test case 2: Valid username that doesn't exist\n    print(f"Test 2 - Non-existent username 'nonexistent': {check_username_exists('nonexistent')}")\n    \n    # Test case 3: Empty string - should return False\n    print(f"Test 3 - Empty string: {check_username_exists('')}")\n    \n    # Test case 4: None input - should return False\n    print(f"Test 4 - None input: {check_username_exists(None)}")\n    \n    # Test case 5: SQL injection attempt - should be safely handled\n    print(f"Test 5 - SQL injection attempt: {check_username_exists(\\"admin' OR '1'='1\\")}")
