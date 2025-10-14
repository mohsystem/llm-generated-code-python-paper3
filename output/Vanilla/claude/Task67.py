
import sqlite3
import sys

class Customer:
    def __init__(self, username, name, email, phone):
        self.username = username
        self.name = name
        self.email = email
        self.phone = phone
    
    def __str__(self):
        return f"Customer(username='{self.username}', name='{self.name}', email='{self.email}', phone='{self.phone}')"

def get_customer_by_username(customer_username):
    customer = None
    conn = None
    
    try:
        conn = sqlite3.connect('customer.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM customer WHERE customerusername = ?", (customer_username,))
        row = cursor.fetchone()
        
        if row:
            customer = Customer(row[0], row[1], row[2], row[3])
    
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
    
    finally:
        if conn:
            conn.close()
    
    return customer

def setup_test_database():
    try:
        conn = sqlite3.connect('customer.db')
        cursor = conn.cursor()
        
        cursor.execute("DROP TABLE IF EXISTS customer")
        cursor.execute("""CREATE TABLE customer (\n                         customerusername TEXT PRIMARY KEY,\n                         name TEXT,\n                         email TEXT,\n                         phone TEXT)""")
        
        test_data = [
            ('user1', 'John Doe', 'john@email.com', '123-456-7890'),
            ('user2', 'Jane Smith', 'jane@email.com', '098-765-4321'),
            ('user3', 'Bob Johnson', 'bob@email.com', '555-555-5555'),
            ('user4', 'Alice Brown', 'alice@email.com', '444-444-4444'),
            ('user5', 'Charlie Davis', 'charlie@email.com', '333-333-3333')
        ]
        
        cursor.executemany("INSERT INTO customer VALUES (?, ?, ?, ?)", test_data)
        conn.commit()
        conn.close()
    
    except sqlite3.Error as e:
        print(f"Error setting up test database: {e}", file=sys.stderr)

if __name__ == "__main__":
    setup_test_database()
    
    test_cases = ['user1', 'user2', 'user3', 'user4', 'nonexistent']
    
    if len(sys.argv) > 1:
        customer = get_customer_by_username(sys.argv[1])
        if customer:
            print(f"Found: {customer}")
        else:
            print(f"Customer not found with username: {sys.argv[1]}")
    else:
        print("Running test cases:")
        for username in test_cases:
            print(f"\\nSearching for: {username}")
            customer = get_customer_by_username(username)
            if customer:
                print(f"Found: {customer}")
            else:
                print("Customer not found")
