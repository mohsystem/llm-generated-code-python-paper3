import sqlite3
from sqlite3 import Error

def setup_database(conn):
    """Create a users table and insert some sample data."""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                full_name TEXT
            );
        """)
        cursor.execute("""
            INSERT INTO users (username, email, full_name) VALUES
            ('alice', 'alice@example.com', 'Alice Smith'),
            ('bob', 'bob@example.com', 'Bob Johnson'),
            ('charlie', 'charlie@example.com', 'Charlie Brown'),
            ('diana', 'diana@example.com', 'Diana Prince');
        """)
        conn.commit()
    except Error as e:
        print(f"Error setting up database: {e}")


def get_user_info(conn, username):
    """
    Connects to the database and retrieves user information.
    :param conn: The database connection object.
    :param username: The username to search for.
    :return: A string containing user information or a "not found" message.
    """
    cursor = conn.cursor()
    # Using a parameterized query to prevent SQL injection
    query = "SELECT username, email, full_name FROM users WHERE username = ?"
    
    try:
        cursor.execute(query, (username,))
        row = cursor.fetchone()
        
        if row:
            result = (
                f"User Found:\n"
                f"  Username: {row[0]}\n"
                f"  Email: {row[1]}\n"
                f"  Full Name: {row[2]}"
            )
        else:
            result = f"User '{username}' not found."
            
        return result
    except Error as e:
        return f"Error executing query: {e}"

def main():
    # Use in-memory SQLite database for a self-contained example
    conn = None
    try:
        conn = sqlite3.connect(":memory:")
        print("Connected to in-memory SQLite database.")
        setup_database(conn)
        
        # 5 Test Cases
        test_usernames = ["alice", "bob", "eve", "charlie", "diana"]
        
        for i, user in enumerate(test_usernames):
            print(f"\n--- Test Case {i + 1} ---")
            print(f"Searching for user: {user}")
            user_info = get_user_info(conn, user)
            print(user_info)

    except Error as e:
        print(f"Database connection failed: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    main()