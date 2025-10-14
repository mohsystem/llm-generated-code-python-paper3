import sqlite3
import sys

def setup_database(conn):
    """Sets up the in-memory database: creates table and inserts sample data."""
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE customer (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                fullname TEXT,
                email TEXT
            )
        """)
        cursor.execute("INSERT INTO customer VALUES (1, 'jdoe', 'John Doe', 'john.doe@example.com')")
        cursor.execute("INSERT INTO customer VALUES (2, 'asmith', 'Alice Smith', 'alice.smith@example.com')")
        cursor.execute("INSERT INTO customer VALUES (3, 'bwhite', 'Bob White', 'bob.white@example.com')")
        cursor.execute("INSERT INTO customer VALUES (4, 'peterpan', 'Peter Pan', 'peter.pan@example.com')")
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database setup failed: {e}", file=sys.stderr)

def get_customer_by_username(conn, customer_username):
    """
    Retrieves customer information using a secure parameterized query.
    
    Args:
        conn: The database connection object.
        customer_username: The username to search for.
    
    Returns:
        A dictionary with customer info if found, otherwise None.
    """
    # Using '?' as a placeholder prevents SQL injection.
    sql = "SELECT id, username, fullname, email FROM customer WHERE username = ?"
    customer_info = None
    try:
        cursor = conn.cursor()
        # The tuple (customer_username,) is passed as the second argument to safely bind the parameter.
        cursor.execute(sql, (customer_username,))
        row = cursor.fetchone()
        
        if row:
            # Unpack row into a structured dictionary
            customer_info = {
                "id": row[0],
                "username": row[1],
                "fullname": row[2],
                "email": row[3]
            }
    except sqlite3.Error as e:
        print(f"Error querying for customer: {e}", file=sys.stderr)
        
    return customer_info

def main():
    """Main function to run the program."""
    # Using an in-memory SQLite database for this example
    conn = sqlite3.connect(':memory:')
    setup_database(conn)

    if len(sys.argv) > 1:
        # If a command-line argument is provided, use it
        username = sys.argv[1]
        print(f"Searching for username from command line: {username}")
        customer = get_customer_by_username(conn, username)
        if customer:
            print(f"Found: {customer}")
        else:
            print(f"Customer with username '{username}' not found.")
    else:
        # Otherwise, run predefined test cases
        print("--- Running Predefined Test Cases ---")
        test_usernames = [
            "jdoe",             # Test Case 1: Existing user
            "asmith",           # Test Case 2: Existing user
            "nonexistent",      # Test Case 3: Non-existing user
            "peterpan",         # Test Case 4: Existing user
            "admin' OR '1'='1"  # Test Case 5: SQL injection attempt
        ]
        
        for username in test_usernames:
            print(f"\nSearching for username: {username}")
            customer = get_customer_by_username(conn, username)
            if customer:
                print(f"Found: {customer}")
            else:
                print(f"Customer with username '{username}' not found.")
                
    conn.close()

if __name__ == "__main__":
    main()