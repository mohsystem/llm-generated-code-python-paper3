import sqlite3
import sys

DB_NAME = "customers.db"

def setup_database():
    """Sets up the database, creates the table, and inserts sample data."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS customer (
        customerid INTEGER PRIMARY KEY AUTOINCREMENT,
        customerusername TEXT NOT NULL UNIQUE,
        firstname TEXT,
        lastname TEXT,
        email TEXT
    );
    """
    cursor.execute(create_table_sql)
    
    customers = [
        ('jdoe', 'John', 'Doe', 'john.doe@email.com'),
        ('asmith', 'Alice', 'Smith', 'alice.s@web.com'),
        ('bwhite', 'Bob', 'White', 'bwhite@mail.org'),
        ('cjones', 'Carol', 'Jones', 'carolj@email.com')
    ]
    
    # Use INSERT OR IGNORE to avoid errors on subsequent runs
    cursor.executemany("INSERT OR IGNORE INTO customer(customerusername, firstname, lastname, email) VALUES(?, ?, ?, ?)", customers)
    
    conn.commit()
    conn.close()

def get_customer_by_username(customer_username):
    """
    Retrieves customer information based on username.
    
    Args:
        customer_username: The username to search for.
        
    Returns:
        A dictionary with customer information if found, otherwise None.
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # To access columns by name
    cursor = conn.cursor()
    
    query = "SELECT customerid, customerusername, firstname, lastname, email FROM customer WHERE customerusername = ?"
    cursor.execute(query, (customer_username,))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return dict(row)
    else:
        return None

def main():
    """Main function to run test cases and handle command-line arguments."""
    setup_database()

    print("--- Running 5 Test Cases ---")
    test_usernames = ["asmith", "jdoe", "nonexistent", "bwhite", "imnotreal"]
    for i, username in enumerate(test_usernames):
        print(f"\nTest Case {i+1}: Searching for '{username}'")
        customer = get_customer_by_username(username)
        if customer:
            print(f"Found: {customer}")
        else:
            print("Customer not found.")
    print("----------------------------\n")

    if len(sys.argv) > 1:
        username_from_arg = sys.argv[1]
        print("--- Running with Command-Line Argument ---")
        print(f"Searching for '{username_from_arg}'")
        customer = get_customer_by_username(username_from_arg)
        if customer:
            print(f"Found: {customer}")
        else:
            print("Customer not found.")
        print("------------------------------------------")

if __name__ == "__main__":
    main()