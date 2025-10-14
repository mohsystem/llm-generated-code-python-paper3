import sqlite3
import sys

def setup_database(conn):
    """Sets up the database with a users table and some sample data."""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE
            );
        """)
        cursor.execute("INSERT INTO users(username, full_name, email) VALUES('alice', 'Alice Smith', 'alice@example.com');")
        cursor.execute("INSERT INTO users(username, full_name, email) VALUES('bob', 'Bob Johnson', 'bob@example.com');")
        cursor.execute("INSERT INTO users(username, full_name, email) VALUES('carol', 'Carol White', 'carol@example.com');")
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database setup error: {e}", file=sys.stderr)
        conn.rollback()


def get_user_info(conn, username):
    """
    Retrieves user information from the database based on the username.
    Uses a parameterized query to prevent SQL injection.

    :param conn: The database connection object.
    :param username: The username to search for.
    :return: A dictionary with user info if found, otherwise None.
    """
    query = "SELECT id, username, full_name, email FROM users WHERE username = ?"
    user_info = None
    try:
        cursor = conn.cursor()
        # The '?' placeholder is replaced by the value in the tuple (username,)
        # This is the safe, parameterized way to execute queries.
        cursor.execute(query, (username,))
        row = cursor.fetchone()
        
        if row:
            user_info = {
                "id": row[0],
                "username": row[1],
                "full_name": row[2],
                "email": row[3]
            }
    except sqlite3.Error as e:
        print(f"Database query failed: {e}", file=sys.stderr)
        
    return user_info

def main():
    # Using an in-memory database for this example
    # The 'with' statement ensures the connection is closed automatically
    try:
        with sqlite3.connect(":memory:") as conn:
            print("Connected to the in-memory SQLite database.")
            setup_database(conn)

            # --- Test Cases ---
            test_usernames = [
                "alice",                # 1. Valid user
                "bob",                  # 2. Another valid user
                "charlie",              # 3. Non-existent user
                "' OR '1'='1' --",      # 4. SQL injection attempt
                ""                      # 5. Empty string username
            ]

            for username in test_usernames:
                print(f"\n--- Searching for user: '{username}' ---")
                found_user = get_user_info(conn, username)
                if found_user:
                    print(f"User found: {found_user}")
                else:
                    print("User not found.")

    except sqlite3.Error as e:
        print(f"Database connection error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()