import sqlite3
import sys
import re
from dataclasses import dataclass
from typing import Optional

# Simple username validation: Alphanumeric, 3-20 characters.
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9]{3,20}$")

@dataclass
class Customer:
    id: int
    username: str
    first_name: str
    last_name: str
    email: str

def setup_database(conn: sqlite3.Connection):
    """Sets up the database with a customer table and sample data."""
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS customer (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE
    );
    """
    
    inserts = [
        ("jdoe", "John", "Doe", "john.doe@example.com"),
        ("asmith", "Alice", "Smith", "alice.smith@example.com"),
        ("bwilliams", "Bob", "Williams", "bob.williams@example.com"),
        ("mjones", "Mary", "Jones", "mary.jones@example.com")
    ]
    
    insert_sql = "INSERT OR IGNORE INTO customer(username, first_name, last_name, email) VALUES(?, ?, ?, ?);"
    
    try:
        cursor = conn.cursor()
        cursor.execute(create_table_sql)
        cursor.executemany(insert_sql, inserts)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database setup error: {e}", file=sys.stderr)
        conn.rollback()

def get_customer_by_username(db_path: str, username: str) -> Optional[Customer]:
    """
    Retrieves customer information for a given username from the database.
    
    Args:
        db_path: Path to the SQLite database file (e.g., ':memory:').
        username: The username to search for.
        
    Returns:
        A Customer object if found, otherwise None.
    """
    if not USERNAME_PATTERN.match(username):
        print(f"Invalid username format: '{username}'", file=sys.stderr)
        return None

    query = "SELECT id, username, first_name, last_name, email FROM customer WHERE username = ?;"
    
    try:
        with sqlite3.connect(db_path) as conn:
            # For demonstration, ensure DB is set up within this connection context
            # In a real app, this would be handled separately.
            setup_database(conn)
            
            cursor = conn.cursor()
            cursor.execute(query, (username,))
            row = cursor.fetchone()
            
            if row:
                return Customer(*row)
    except sqlite3.Error as e:
        print(f"Database query error: {e}", file=sys.stderr)
    
    return None

def main():
    """Main function to handle command-line arguments and run test cases."""
    db_path = ":memory:" # Use in-memory database for this example

    if len(sys.argv) > 1:
        username = sys.argv[1]
        print(f"Searching for username from command line argument: {username}")
        customer = get_customer_by_username(db_path, username)
        if customer:
            print(f"Found: {customer}")
        else:
            print("Customer not found.")
    else:
        print("Running test cases...")
        test_usernames = ["jdoe", "asmith", "bwilliams", "enonexistent", "mjones"]
        
        for i, username in enumerate(test_usernames):
            print(f"\n--- Test Case {i + 1}: Searching for username '{username}' ---")
            customer = get_customer_by_username(db_path, username)
            if customer:
                print(f"Found: {customer}")
            else:
                print("Customer not found.")

if __name__ == "__main__":
    main()