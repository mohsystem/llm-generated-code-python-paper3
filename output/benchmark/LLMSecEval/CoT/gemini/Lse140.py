import sqlite3
import os

DB_FILE = "users_python.db"

def setup_database():
    """
    Sets up the database by creating a users table and inserting sample data.
    This is for demonstration purposes to make the example runnable.
    """
    try:
        # Connect to SQLite database (it will be created if it doesn't exist)
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Create table if it doesn't exist
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE
            )
            """)
            
            # Sample users to insert
            sample_users = [('alice',), ('bob',), ("O'Malley",)]
            
            # Insert sample data, ignoring if it already exists
            cursor.executemany("INSERT OR IGNORE INTO users (username) VALUES (?)", sample_users)
            
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database setup error: {e}")


def username_exists(username: str) -> bool:
    """
    Checks if a username exists in the database.

    Args:
        username: The username to check.

    Returns:
        True if the username exists, False otherwise.
    """
    # Using `SELECT 1` is efficient as we only care about existence, not the data.
    # The `?` is a placeholder for the parameter to prevent SQL injection.
    sql = "SELECT 1 FROM users WHERE username = ? LIMIT 1"
    
    conn = None
    try:
        # The 'with' statement ensures the connection is closed automatically.
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Execute the query with the username as a parameter.
            # This is the key step to prevent SQL injection.
            cursor.execute(sql, (username,))
            
            # fetchone() returns a row (as a tuple) if found, otherwise None.
            result = cursor.fetchone()
            
            # If a result is found, it's not None, so the expression returns True.
            return result is not None
    except sqlite3.Error as e:
        # In a real application, you would log this error.
        print(f"SQL Error: {e}")
        # Return false in case of any database error for security.
        return False

def main():
    """Main function with test cases."""
    # Create and populate the database for the example
    setup_database()

    # --- Test Cases ---
    test_usernames = ["alice", "bob", "charlie", "O'Malley", ""]
    
    print("--- Python Test Cases ---")
    for user in test_usernames:
        exists = username_exists(user)
        print(f"Does username '{user}' exist? {exists}")
    
    # Clean up the created database file
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

if __name__ == '__main__':
    main()