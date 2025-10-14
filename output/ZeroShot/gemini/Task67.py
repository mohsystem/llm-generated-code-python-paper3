import sqlite3
import sys
from dataclasses import dataclass

@dataclass
class Customer:
    """A class to hold customer data."""
    username: str
    first_name: str
    last_name: str
    email: str

DB_NAME = "customers.db"

def setup_database():
    """Sets up the database, creates table, and populates with sample data."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS customer (
        customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
        customerusername TEXT NOT NULL UNIQUE,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE
    )""")
    
    # Clear existing data for a clean run
    cursor.execute("DELETE FROM customer")

    sample_data = [
        ('jdoe', 'John', 'Doe', 'john.doe@example.com'),
        ('asmith', 'Anna', 'Smith', 'anna.smith@example.com'),
        ('sjobs', 'Steve', 'Jobs', 's.jobs@example.com'),
        ('bgates', 'Bill', 'Gates', 'bill.g@example.com'),
    ]

    cursor.executemany("INSERT INTO customer(customerusername, first_name, last_name, email) VALUES (?, ?, ?, ?)", sample_data)
    
    conn.commit()
    conn.close()

def get_customer_by_username(username: str) -> Customer | None:
    """
    Retrieves a customer from the database by username using a parameterized query.
    
    Args:
        username: The username of the customer to find.
        
    Returns:
        A Customer object if found, otherwise None.
    """
    conn = None
    customer = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # The '?' is a placeholder. The database driver handles quoting and escaping,
        # preventing SQL injection.
        sql_query = "SELECT customerusername, first_name, last_name, email FROM customer WHERE customerusername = ?"
        
        # Pass parameters as a tuple to the execute method.
        cursor.execute(sql_query, (username,))
        
        row = cursor.fetchone()
        
        if row:
            customer = Customer(username=row[0], first_name=row[1], last_name=row[2], email=row[3])
            
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
    finally:
        if conn:
            conn.close()
            
    return customer

def main():
    """Main function to set up DB and run test cases."""
    setup_database()

    test_usernames = []

    # Check for command-line arguments
    if len(sys.argv) > 1:
        print("--- Running with provided command-line argument ---")
        test_usernames.append(sys.argv[1])
    else:
        # Use built-in test cases if no arguments are provided
        print("--- Running 5 built-in test cases ---")
        test_usernames = [
            "jdoe",            # Test Case 1: Existing user
            "asmith",          # Test Case 2: Another existing user
            "nonexistent",     # Test Case 3: Non-existent user
            "sjobs",           # Test Case 4: A third existing user
            "' OR 1=1; --"     # Test Case 5: SQL injection attempt (should fail safely)
        ]

    for username in test_usernames:
        print(f"\nSearching for username: '{username}'")
        cust = get_customer_by_username(username)
        if cust:
            print(f"Found: {cust}")
        else:
            print("Result: Customer not found.")

if __name__ == "__main__":
    main()