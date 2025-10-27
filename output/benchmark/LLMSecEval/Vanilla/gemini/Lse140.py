import sqlite3

def check_username_exists(conn, username):
    """
    Checks if a username exists in the users table.

    :param conn: The database connection object.
    :param username: The username to check.
    :return: True if the username exists, False otherwise.
    """
    try:
        cursor = conn.cursor()
        # Use a parameterized query to prevent SQL injection
        query = "SELECT 1 FROM users WHERE username = ? LIMIT 1"
        cursor.execute(query, (username,))
        # fetchone() returns a row if one is found, otherwise None
        return cursor.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def main():
    """
    Main function to set up the database, run test cases, and clean up.
    """
    # Use an in-memory SQLite database for this example
    conn = None
    try:
        conn = sqlite3.connect(':memory:')
        print("In-memory SQLite database connection established.")
        
        cursor = conn.cursor()

        # Create a simple 'users' table
        cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE
        )
        """)

        # Insert some sample data
        sample_users = [('alice',), ('bob',), ('carol',)]
        cursor.executemany("INSERT INTO users (username) VALUES (?)", sample_users)
        conn.commit()
        print("Database setup complete.")

        # --- Test Cases ---
        print("\n--- Running Test Cases ---")
        
        # Test Case 1: Username that exists
        user1 = "alice"
        print(f"1. Checking for username '{user1}': {'Exists' if check_username_exists(conn, user1) else 'Does not exist'}")

        # Test Case 2: Username that does not exist
        user2 = "david"
        print(f"2. Checking for username '{user2}': {'Exists' if check_username_exists(conn, user2) else 'Does not exist'}")

        # Test Case 3: Another username that exists
        user3 = "bob"
        print(f"3. Checking for username '{user3}': {'Exists' if check_username_exists(conn, user3) else 'Does not exist'}")

        # Test Case 4: Case-sensitive check (should not exist)
        user4 = "Alice"
        print(f"4. Checking for username '{user4}': {'Exists' if check_username_exists(conn, user4) else 'Does not exist'}")
        
        # Test Case 5: Empty string username
        user5 = ""
        print(f"5. Checking for username '{user5}': {'Exists' if check_username_exists(conn, user5) else 'Does not exist'}")


    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()
            print("\nDatabase connection closed.")

if __name__ == '__main__':
    main()