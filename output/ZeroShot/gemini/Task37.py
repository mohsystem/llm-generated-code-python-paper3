import sqlite3
import os

DB_FILE = "user_database_py.db"

def setup_database(conn):
    """Sets up the database by creating a table and inserting sample data."""
    try:
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL
            )
        """)
        users_to_insert = [
            ('alice', 'Alice Smith', 'alice@example.com'),
            ('bob', 'Bob Johnson', 'bob@example.com'),
            ('admin', 'Administrator', 'admin@example.org')
        ]
        cursor.executemany("INSERT INTO users (username, full_name, email) VALUES (?, ?, ?)", users_to_insert)
        conn.commit()
        print("Database setup successful.")
    except sqlite3.Error as e:
        print(f"Database setup error: {e}")

def get_user_info(conn, username):
    """
    Retrieves user information from the database using a parameterized query.
    :param conn: The database connection object.
    :param username: The username to search for.
    :return: A dictionary with user data, or None if not found.
    """
    try:
        cursor = conn.cursor()
        # The '?' placeholder prevents SQL injection.
        # The second argument to execute() must be a tuple.
        cursor.execute("SELECT id, username, full_name, email FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        
        if row:
            return { "id": row[0], "username": row[1], "full_name": row[2], "email": row[3] }
        else:
            return None
    except sqlite3.Error as e:
        print(f"Query error: {e}")
        return None

def main():
    """Main function to run test cases."""
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        setup_database(conn)

        print("\n--- Running 5 Test Cases ---")
        
        test_usernames = [
            "alice",
            "bob",
            "charlie",
            "admin",
            "' OR '1'='1"
        ]
        
        for i, username in enumerate(test_usernames):
            print(f"\n[Test Case {i+1}]")
            print(f"Searching for user: '{username}'")
            user_info = get_user_info(conn, username)
            if user_info:
                print("Result: User found:")
                print(f"  ID: {user_info['id']}")
                print(f"  Username: {user_info['username']}")
                print(f"  Full Name: {user_info['full_name']}")
                print(f"  Email: {user_info['email']}")
            else:
                print("Result: User not found.")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            conn.close()
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

if __name__ == "__main__":
    main()