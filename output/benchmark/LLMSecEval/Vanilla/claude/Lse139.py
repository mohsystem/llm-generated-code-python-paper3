
import os
import sqlite3
import mysql.connector
from typing import Optional

def is_moderator(username: str) -> bool:
    db_url = os.getenv("DB_URL")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME")
    
    if not all([db_url, db_user, db_password]):
        print("Database credentials not found in environment variables")
        return False
    
    conn = None
    cursor = None
    
    try:
        # Assuming MySQL/MariaDB connection
        conn = mysql.connector.connect(
            host=db_url,
            user=db_user,
            password=db_password,
            database=db_name
        )
        cursor = conn.cursor()
        
        query = "SELECT is_moderator FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        
        if result:
            return bool(result[0])
        return False
        
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    # Test cases
    print(f"Test 1: {is_moderator('admin')}")
    print(f"Test 2: {is_moderator('moderator1')}")
    print(f"Test 3: {is_moderator('user123')}")
    print(f"Test 4: {is_moderator('guest')}")
    print(f"Test 5: {is_moderator('nonexistent')}")
