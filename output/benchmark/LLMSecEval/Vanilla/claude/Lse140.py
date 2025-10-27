
import sqlite3
import mysql.connector
from typing import Optional

def check_username_exists(username: str, db_path: str = None, db_config: dict = None, db_type: str = 'sqlite') -> bool:
    """\n    Check if username exists in database\n    \n    Args:\n        username: Username to check\n        db_path: Path to SQLite database (for SQLite)\n        db_config: Dictionary with host, user, password, database (for MySQL)\n        db_type: Type of database ('sqlite' or 'mysql')\n    \n    Returns:\n        True if username exists, False otherwise\n    """
    conn = None
    cursor = None
    
    try:
        if db_type == 'sqlite':
            # Connect to SQLite database
            conn = sqlite3.connect(db_path if db_path else ':memory:')
        else:
            # Connect to MySQL database
            conn = mysql.connector.connect(**db_config)
        
        cursor = conn.cursor()
        
        # Execute query to check if username exists
        query = "SELECT COUNT(*) FROM users WHERE username = ?"
        if db_type == 'mysql':
            query = "SELECT COUNT(*) FROM users WHERE username = %s"
        
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        
        return result[0] > 0 if result else False
        
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    # For SQLite example
    db_path = "test.db"
    
    # For MySQL example
    db_config = {
        'host': 'localhost',
        'user': 'root',
        'password': 'password',
        'database': 'testdb'
    }
    
    # Test cases
    print("Test 1:", check_username_exists("john_doe", db_path=db_path, db_type='sqlite'))
    print("Test 2:", check_username_exists("jane_smith", db_path=db_path, db_type='sqlite'))
    print("Test 3:", check_username_exists("admin", db_path=db_path, db_type='sqlite'))
    print("Test 4:", check_username_exists("test_user", db_path=db_path, db_type='sqlite'))
    print("Test 5:", check_username_exists("nonexistent", db_path=db_path, db_type='sqlite'))
