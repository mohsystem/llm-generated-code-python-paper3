
import os
import sys
from typing import Optional

# Use cryptographically secure database connection library
# For MySQL/MariaDB, use mysql-connector-python or PyMySQL
# For PostgreSQL, use psycopg2
# This example uses mysql-connector-python

def is_user_moderator(username: str) -> bool:
    """\n    Check if a user is a moderator by querying the database.\n    Uses environment variables for database credentials.\n    \n    Args:\n        username: The username to check\n        \n    Returns:\n        True if user is a moderator, False otherwise\n        \n    Raises:\n        ValueError: If username is invalid\n        RuntimeError: If database credentials are not set\n    """
    # Validate input (Rules#8)
    if username is None or not isinstance(username, str):
        raise ValueError("Username must be a non-null string")
    
    if not username.strip():
        raise ValueError("Username cannot be empty")
    
    # Limit username length to prevent potential attacks (Rules#8)
    if len(username) > 255:
        raise ValueError("Username exceeds maximum length")
    
    # Retrieve database credentials from environment variables (Rules#4, Rules#5)
    db_host = os.environ.get('DB_HOST')
    db_name = os.environ.get('DB_NAME')
    db_user = os.environ.get('DB_USER')
    db_password = os.environ.get('DB_PASSWORD')
    db_port = os.environ.get('DB_PORT', '3306')
    
    # Validate that credentials are available (Rules#8)
    if not all([db_host, db_name, db_user, db_password]):
        raise RuntimeError("Database credentials not found in environment variables")
    
    try:
        # Import here to handle missing dependencies gracefully
        import mysql.connector
        from mysql.connector import Error
        
        # Establish database connection with proper resource management (Rules#11)
        # Using context manager for automatic cleanup
        connection = mysql.connector.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=int(db_port)
        )
        
        if not connection.is_connected():
            return False
        
        cursor = connection.cursor()
        
        # Use parameterized query to prevent SQL injection (Rules#1)
        # Assuming table structure: users(username, is_moderator)
        query = "SELECT is_moderator FROM users WHERE username = %s LIMIT 1"
        
        # Execute with parameter binding (Rules#1)
        cursor.execute(query, (username,))
        
        # Fetch result
        result = cursor.fetchone()
        
        # Close cursor and connection properly (Rules#11)
        cursor.close()
        connection.close()
        
        # Return boolean result
        if result:
            return bool(result[0])
        
        return False
        
    except Exception as e:
        # Log error securely without exposing sensitive details (Rules#1)
        print("Database error occurred while checking moderator status", file=sys.stderr)
        # In production, use proper logging framework
        return False
    
    finally:
        # Ensure connection is closed even on error (Rules#11)
        try:
            if 'connection' in locals() and connection.is_connected():
                connection.close()
        except:
            pass


def main():
    """Test cases for the is_user_moderator function."""
    # For testing purposes only - set environment variables
    os.environ['DB_HOST'] = 'localhost'
    os.environ['DB_NAME'] = 'testdb'
    os.environ['DB_USER'] = 'testuser'
    os.environ['DB_PASSWORD'] = 'testpass'
    os.environ['DB_PORT'] = '3306'
    
    # Test case 1: Valid moderator user
    print(f"Test 1 - Valid moderator: {is_user_moderator('admin_user')}")
    
    # Test case 2: Valid non-moderator user
    print(f"Test 2 - Regular user: {is_user_moderator('regular_user')}")
    
    # Test case 3: Non-existent user
    print(f"Test 3 - Non-existent user: {is_user_moderator('nonexistent')}")
    
    # Test case 4: Empty username (should raise exception)
    try:
        is_user_moderator("")
    except ValueError as e:
        print(f"Test 4 - Empty username: Exception caught as expected")
    
    # Test case 5: Null username (should raise exception)
    try:
        is_user_moderator(None)
    except ValueError as e:
        print(f"Test 5 - Null username: Exception caught as expected")


if __name__ == "__main__":
    main()
