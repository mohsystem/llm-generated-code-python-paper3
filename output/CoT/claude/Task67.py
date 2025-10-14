
import sys
import re
import sqlite3
from dataclasses import dataclass
from typing import Optional

@dataclass
class Customer:
    id: int
    username: str
    email: str
    full_name: str
    
    def __str__(self):
        return f"Customer(id={self.id}, username='{self.username}', email='{self.email}', full_name='{self.full_name}')"

def get_customer_by_username(customer_username: str) -> Optional[Customer]:
    """\n    Securely retrieve customer information by username using parameterized queries.\n    """
    # Input validation
    if not customer_username or not customer_username.strip():
        print("Error: Username cannot be null or empty", file=sys.stderr)
        return None
    
    # Sanitize input (allow only alphanumeric and underscore)
    if not re.match(r'^[a-zA-Z0-9_]{1,50}$', customer_username):
        print("Error: Invalid username format", file=sys.stderr)
        return None
    
    conn = None
    cursor = None
    customer = None
    
    try:
        # Database connection (using SQLite for demonstration)
        # Replace with your actual database connection
        conn = sqlite3.connect('customer.db')
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        query = "SELECT id, username, email, full_name FROM customer WHERE username = ?"
        cursor.execute(query, (customer_username,))
        
        row = cursor.fetchone()
        
        if row:
            customer = Customer(
                id=row[0],
                username=row[1],
                email=row[2],
                full_name=row[3]
            )
        else:
            print(f"No customer found with username: {customer_username}")
            
    except sqlite3.Error as e:
        # Secure error handling - don't expose sensitive details
        print("Database error occurred while retrieving customer information", file=sys.stderr)
        print(f"Error details: {e}", file=sys.stderr)
    
    finally:
        # Proper resource cleanup
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return customer

def main():
    """Main function with test cases."""
    # Test cases
    test_usernames = ["john_doe", "jane_smith", "admin123", "test_user", "nonexistent"]
    
    if len(sys.argv) > 1:
        # Use command line argument
        customer = get_customer_by_username(sys.argv[1])
        if customer:
            print(f"Retrieved: {customer}")
    else:
        # Run test cases
        print("Running test cases...\\n")
        for username in test_usernames:
            print(f"Testing username: {username}")
            customer = get_customer_by_username(username)
            if customer:
                print(f"Result: {customer}")
            print("---")

if __name__ == "__main__":
    main()
