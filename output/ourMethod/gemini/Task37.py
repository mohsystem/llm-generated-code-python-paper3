import sqlite3
import re
from typing import Optional, Tuple

def initialize_database(conn: sqlite3.Connection):
    """Initializes the database with a users table and some sample data."""
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        full_name TEXT NOT NULL
    );
    """
    insert_data_sql = """
    INSERT INTO users(username, email, full_name) VALUES
    ('alice', 'alice@example.com', 'Alice Smith'),
    ('bob', 'bob@example.com', 'Bob Johnson');
    """
    try:
        with conn:
            conn.execute(create_table_sql)
            try:
                conn.execute(insert_data_sql)
            except sqlite3.IntegrityError:
                # Data likely already exists, which is fine for this example.
                pass
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
        raise

def is_valid_username(username: str) -> bool:
    """Validates the username format (3-16 alphanumeric characters)."""
    if not isinstance(username, str):
        return False
    return re.match(r"^[a-zA-Z0-9]{3,16}$", username) is not None

def get_user_info(conn: sqlite3.Connection, username: str) -> str:
    """
    Retrieves user information for a given username using a parameterized query
    to prevent SQL injection.
    """
    if not is_valid_username(username):
        return "Invalid username format."

    sql = "SELECT id, username, email, full_name FROM users WHERE username = ?"
    result_str = ""
    try:
        cursor = conn.cursor()
        # The comma in (username,) is crucial to make it a tuple.
        cursor.execute(sql, (username,))
        row = cursor.fetchone()

        if row:
            result_str = (f"User Found:\n"
                        f"  ID: {row[0]}\n"
                        f"  Username: {row[1]}\n"
                        f"  Email: {row[2]}\n"
                        f"  Full Name: {row[3]}")
        else:
            result_str = f"User not found: {username}"
    except sqlite3.Error as e:
        # In a real application, log this error to a secure logging system.
        print(f"Database query failed: {e}")
        return "Error executing query."
    
    return result_str

def main():
    """Main function to set up DB, run tests, and close connection."""
    conn = None
    try:
        # Use an in-memory SQLite database for this example.
        conn = sqlite3.connect(":memory:")
        initialize_database(conn)

        print("--- Test Cases ---")
        
        # Test Case 1: Valid, existing user
        print("Test 1: Searching for 'alice'")
        print(get_user_info(conn, "alice"))
        print("--------------------")

        # Test Case 2: Another valid, existing user
        print("Test 2: Searching for 'bob'")
        print(get_user_info(conn, "bob"))
        print("--------------------")

        # Test Case 3: Valid, but non-existent user
        print("Test 3: Searching for 'charlie'")
        print(get_user_info(conn, "charlie"))
        print("--------------------")

        # Test Case 4: Invalid username format (contains symbols)
        print("Test 4: Searching for 'user!'")
        print(get_user_info(conn, "user!"))
        print("--------------------")

        # Test Case 5: Classic SQL injection attempt.
        # This is safely handled by parameter substitution.
        print("Test 5: Searching for \"admin' OR '1'='1'\"")
        print(get_user_info(conn, "admin' OR '1'='1'"))
        print("--------------------")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    main()