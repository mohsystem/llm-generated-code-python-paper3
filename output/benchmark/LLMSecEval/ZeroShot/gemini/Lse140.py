import sqlite3
import os

DB_FILE = "user_database.db"

def setup_database():
    """Sets up the database by creating a users table and inserting sample data."""
    # Remove the database file if it exists to start fresh for the demo
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        
    # The 'with' statement ensures the connection is automatically closed
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Create a simple users table
            cursor.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE
                )
            """)
            
            # Insert sample data
            sample_users = [('alice',), ('bob',), ('charlie',)]
            cursor.executemany("INSERT INTO users (username) VALUES (?)", sample_users)
            
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database setup error: {e}")


def username_exists(username: str) -> bool:
    """
    Securely checks if a username exists in the database.
    Uses parameterized queries to prevent SQL injection.

    :param username: The username to check.
    :return: True if the username exists, False otherwise.
    """
    # The '?' is a placeholder for the parameter. This is the safe way to pass data.
    sql = "SELECT 1 FROM users WHERE username = ?"
    
    try:
        # NOTE: In a real-world application, connection details should not be hardcoded.
        # Use a configuration file or environment variables.
        # The 'with' statement handles closing the connection automatically.
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # The second argument to execute() must be a tuple.
            # The library safely substitutes the '?' with the value from the tuple.
            cursor.execute(sql, (username,))
            
            # fetchone() returns a row if found, otherwise None.
            return cursor.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Database query error: {e}")
        return False

# Main execution block with 5 test cases
if __name__ == "__main__":
    setup_database()

    print("--- Python Test Cases ---")

    # Test Case 1: Check for an existing user
    user1 = "alice"
    print(f"Does '{user1}' exist? {username_exists(user1)}")  # Expected: True

    # Test Case 2: Check for a non-existent user
    user2 = "david"
    print(f"Does '{user2}' exist? {username_exists(user2)}")  # Expected: False

    # Test Case 3: Check for another existing user (case-sensitive)
    user3 = "Bob"
    print(f"Does '{user3}' exist? {username_exists(user3)}")  # Expected: False

    # Test Case 4: SQL Injection attempt. Should be handled safely.
    user4 = "' OR '1'='1"
    print(f"Does '{user4}' exist? {username_exists(user4)}")  # Expected: False

    # Test Case 5: Check for an empty string
    user5 = ""
    print(f"Does '{user5}' exist? {username_exists(user5)}")  # Expected: False