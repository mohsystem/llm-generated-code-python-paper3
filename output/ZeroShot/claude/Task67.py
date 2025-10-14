
import sqlite3
import sys
from typing import Optional, Dict

class Customer:
    def __init__(self, username: str, name: str, email: str, phone: str):
        self.username = username
        self.name = name
        self.email = email
        self.phone = phone
    
    def __str__(self):
        return f"Customer{{username='{self.username}', name='{self.name}', email='{self.email}', phone='{self.phone}'}}"
    
    def to_dict(self) -> Dict:
        return {
            'username': self.username,
            'name': self.name,
            'email': self.email,
            'phone': self.phone
        }

def get_customer_by_username(customer_username: str) -> Optional[Customer]:
    if not customer_username or not customer_username.strip():
        return None
    
    db_path = 'customer.db'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        query = "SELECT username, name, email, phone FROM customer WHERE username = ?"
        cursor.execute(query, (customer_username,))
        
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            return Customer(row[0], row[1], row[2], row[3])
        
        return None
        
    except sqlite3.Error as e:
        print(f"Database error: {e}", file=sys.stderr)
        return None

def initialize_database():
    try:
        conn = sqlite3.connect('customer.db')
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS customer (\n                         username TEXT PRIMARY KEY,\n                         name TEXT,\n                         email TEXT,\n                         phone TEXT)''')
        
        cursor.execute("DELETE FROM customer")
        
        test_data = [
            ('john_doe', 'John Doe', 'john@example.com', '555-0101'),
            ('jane_smith', 'Jane Smith', 'jane@example.com', '555-0102'),
            ('bob_wilson', 'Bob Wilson', 'bob@example.com', '555-0103'),
            ('alice_brown', 'Alice Brown', 'alice@example.com', '555-0104'),
            ('charlie_davis', 'Charlie Davis', 'charlie@example.com', '555-0105')
        ]
        
        cursor.executemany("INSERT INTO customer VALUES (?, ?, ?, ?)", test_data)
        
        conn.commit()
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}", file=sys.stderr)

if __name__ == "__main__":
    initialize_database()
    
    test_cases = ["john_doe", "jane_smith", "bob_wilson", "nonexistent_user", ""]
    
    if len(sys.argv) > 1:
        customer = get_customer_by_username(sys.argv[1])
        if customer:
            print(f"Found: {customer}")
        else:
            print(f"Customer not found: {sys.argv[1]}")
    else:
        print("Running test cases:")
        for username in test_cases:
            print(f"\\nSearching for: '{username}'")
            customer = get_customer_by_username(username)
            if customer:
                print(f"Result: {customer}")
            else:
                print("Result: Customer not found")
