
import re
import sqlite3
import os
from typing import Optional

# Secure input validation patterns
STOCK_NAME_PATTERN = re.compile(r'^[A-Za-z0-9._-]{1,10}$')
USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_]{3,50}$')
MAX_QUANTITY = 1000000
MIN_QUANTITY = 1


def insert_buy_order(username: str, stock_name: str, stock_quantity: int) -> bool:
    """\n    Securely insert a buy order into the database.\n    All inputs are validated before processing.\n    """
    # Input validation: check for None and empty strings
    if not username or not isinstance(username, str):
        print("Invalid username", file=__import__('sys').stderr)
        return False
    
    if not stock_name or not isinstance(stock_name, str):
        print("Invalid stock name", file=__import__('sys').stderr)
        return False
    
    # Validate username format and length
    username = username.strip()
    if not USERNAME_PATTERN.match(username):
        print("Username must be 3-50 alphanumeric characters or underscore", 
              file=__import__('sys').stderr)
        return False
    
    # Validate stock name format to prevent injection
    stock_name = stock_name.strip()
    if not STOCK_NAME_PATTERN.match(stock_name):
        print("Invalid stock name format", file=__import__('sys').stderr)
        return False
    
    # Validate quantity type and range
    if not isinstance(stock_quantity, int):
        print("Quantity must be an integer", file=__import__('sys').stderr)
        return False
    
    if stock_quantity < MIN_QUANTITY or stock_quantity > MAX_QUANTITY:
        print(f"Quantity must be between {MIN_QUANTITY} and {MAX_QUANTITY}", 
              file=__import__('sys').stderr)
        return False
    
    conn = None
    cursor = None
    
    try:
        # Get database path from environment variable (secure configuration)
        db_path = os.getenv('DB_PATH', 'orders.db')
        
        # Validate database path to prevent directory traversal
        if '..' in db_path or db_path.startswith('/'):
            print("Invalid database path", file=__import__('sys').stderr)
            return False
        
        # Connect to database with secure settings
        conn = sqlite3.connect(db_path, timeout=10.0)
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        sql = """INSERT INTO buy_orders (username, stock_name, quantity, order_date) \n                 VALUES (?, ?, ?, datetime('now'))"""
        
        # Execute with validated parameters
        cursor.execute(sql, (username, stock_name, stock_quantity))
        conn.commit()
        
        if cursor.rowcount > 0:
            print("Order inserted successfully")
            return True
        else:
            print("Failed to insert order", file=__import__('sys').stderr)
            return False
            
    except sqlite3.Error as e:
        # Log error without exposing sensitive details
        print("Database error occurred", file=__import__('sys').stderr)
        if conn:
            conn.rollback()
        return False
    except Exception as e:
        print("Unexpected error occurred", file=__import__('sys').stderr)
        return False
    finally:
        # Clean up resources
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def main():
    """Test cases for insert_buy_order function"""
    # Test case 1: Valid input
    print(f"Test 1: {insert_buy_order('john_doe', 'AAPL', 100)}")
    
    # Test case 2: Valid input with different stock
    print(f"Test 2: {insert_buy_order('jane_smith', 'GOOGL', 50)}")
    
    # Test case 3: Invalid stock name (SQL injection attempt)
    print(f"Test 3: {insert_buy_order('user123', "AAPL'; DROP TABLE--\\", 10)}")

    # Test case 4: Invalid quantity (negative)
    print(f"Test 4: {insert_buy_order('alice_w', 'MSFT', -5)}")

    # Test case 5: Invalid quantity (exceeds maximum)
    print(f"Test 5: {insert_buy_order('bob_jones', 'TSLA', 2000000)}")


if __name__ == "__main__":
    main()
