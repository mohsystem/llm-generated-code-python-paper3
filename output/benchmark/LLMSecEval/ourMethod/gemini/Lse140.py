import sqlite3
import os
import re
import sys

# Rule #1: Validate username format: 3-20 characters, alphanumeric and underscores.
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")

def check_username_exists(db_connection, username):
    """
    Executes a query to check if the username exists in the database.

    Args:
        db_connection: An active sqlite3 database connection object.
        username: The username to check.

    Returns:
        True if the username exists, False otherwise.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(username, str) or not USERNAME_REGEX.match(username):
        print(f"Invalid username format: '{username}'", file=sys.stderr)
        return False

    exists = False
    # Using a parameterized query to prevent SQL injection (CWE-89).
    query = "SELECT 1 FROM users WHERE username = ? LIMIT 1"

    try:
        # The 'with' statement ensures the connection is managed properly.
        cursor = db_connection.cursor()
        cursor.execute(query, (username,))
        # fetchone() returns a row or None
        if cursor.fetchone():
            exists = True
    except sqlite3.Error as e:
        # Rule #7: Return generic messages, log detailed ones securely.
        print(f"Database query failed: {e}", file=sys.stderr)
    
    return exists

def setup_database(db_path):
    """Creates and populates a temporary database for testing."""
    if os.path.exists(db_path):
        os.remove(db_path)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Create table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE
            )
        ''')
        # Insert some data
        users_to_add = [('alice',), ('bob',)]
        cursor.executemany('INSERT INTO users (username) VALUES (?)', users_to_add)
        conn.commit()
        print(f"Database '{db_path}' created and populated for testing.")
        return conn
    except sqlite3.Error as e:
        print(f"Failed to set up database: {e}", file=sys.stderr)
        return None

def main():
    """Main function with test cases."""
    print("--- Running Python Username Existence Check ---")
    DB_FILE = "test_users.db"
    
    # Setup database and connection for testing
    conn = setup_database(DB_FILE)
    if not conn:
        print("Exiting due to database setup failure.", file=sys.stderr)
        return

    # Test cases
    test_cases = [
        ("alice", True),        # Test case 1: Existing user
        ("charlie", False),     # Test case 2: Non-existent user
        ("dave_has_a_very_long_name_that_is_invalid", False), # Test case 3: Invalid (too long)
        ("eve-vil", False),     # Test case 4: Invalid (contains '-')
        ("", False)             # Test case 5: Invalid (empty)
    ]
    
    for i, (username, expected) in enumerate(test_cases):
        print(f"Test Case {i+1}: Checking for username '{username}'...")
        exists = check_username_exists(conn, username)
        print(f"Result: Username '{username}' {'exists' if exists else 'does not exist or is invalid'}.")
        assert exists == expected
        print("Assertion Passed.\n")

    # Clean up
    conn.close()
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    print("Test database cleaned up.")


if __name__ == "__main__":
    main()