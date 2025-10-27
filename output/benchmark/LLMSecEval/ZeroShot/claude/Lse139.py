
import os
import sys
from typing import Optional

def is_user_moderator(username: str) -> bool:
    """\n    Check if a user is a moderator by querying the database.\n    \n    Args:\n        username: The username to check\n        \n    Returns:\n        True if the user is a moderator, False otherwise\n    """
    try:
        import psycopg2  # For PostgreSQL, can be changed to mysql.connector, sqlite3, etc.
    except ImportError:
        print("Database driver not installed. Install with: pip install psycopg2-binary")
        return False
    
    db_url = os.getenv("DB_URL")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    
    if not all([db_url, db_user, db_password]):
        print("Database credentials not found in environment variables", file=sys.stderr)
        return False
    
    query = "SELECT is_moderator FROM users WHERE username = %s"
    
    try:
        conn = psycopg2.connect(
            host=db_url,
            user=db_user,
            password=db_password
        )
        
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if result:
            return bool(result[0])
        
        return False
        
    except Exception as e:
        print(f"Database error: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    # Test cases
    print(f"Test 1: {is_user_moderator('admin_user')}")
    print(f"Test 2: {is_user_moderator('moderator1')}")
    print(f"Test 3: {is_user_moderator('regular_user')}")
    print(f"Test 4: {is_user_moderator('test_mod')}")
    print(f"Test 5: {is_user_moderator('guest_user')}")
