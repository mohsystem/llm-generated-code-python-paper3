
import sqlite3
import re
from typing import Optional

USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,30}$')
STOCK_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\\-\\.]{1,20}$')

def validate_username(username: str) -> bool:
    return username is not None and USERNAME_PATTERN.match(username) is not None

def validate_stock_name(stock_name: str) -> bool:
    return stock_name is not None and STOCK_NAME_PATTERN.match(stock_name) is not None

def validate_quantity(quantity: int) -> bool:
    return isinstance(quantity, int) and 0 < quantity <= 1000000

def insert_buy_order(username: str, stock_name: str, stock_quantity: int) -> str:
    if not validate_username(username):
        return "Error: Invalid username format"
    if not validate_stock_name(stock_name):
        return "Error: Invalid stock name format"
    if not validate_quantity(stock_quantity):
        return "Error: Invalid quantity (must be 1-1000000)"
    
    try:
        conn = sqlite3.connect('stock_orders.db')
        cursor = conn.cursor()
        
        # Using parameterized query to prevent SQL injection
        insert_sql = """\n        INSERT INTO buy_orders (username, stock_name, quantity, order_date) \n        VALUES (?, ?, ?, datetime('now'))\n        """
        
        cursor.execute(insert_sql, (username, stock_name, stock_quantity))
        conn.commit()
        
        if cursor.rowcount > 0:
            result = f"redirect:/profile?user={username}"
        else:
            result = "Error: Failed to insert order"
        
        cursor.close()
        conn.close()
        
        return result
        
    except sqlite3.Error as e:
        return f"Error: Database error - {str(e)}"

if __name__ == "__main__":
    print("=== Stock Order System Test Cases ===\\n")
    
    # Test Case 1: Valid order
    print("Test 1 - Valid order:")
    print(insert_buy_order("john_doe", "AAPL", 100))
    
    # Test Case 2: Another valid order
    print("\\nTest 2 - Valid order with different stock:")
    print(insert_buy_order("jane_smith", "GOOGL", 50))
    
    # Test Case 3: Invalid username (special chars)
    print("\\nTest 3 - Invalid username:")
    print(insert_buy_order("user@123", "MSFT", 75))
    
    # Test Case 4: Invalid stock name (SQL injection attempt)
    print("\\nTest 4 - Invalid stock name:")
    print(insert_buy_order("testuser", "STOCK'; DROP TABLE--", 25))
    
    # Test Case 5: Invalid quantity (negative)
    print("\\nTest 5 - Invalid quantity:")
    print(insert_buy_order("alice", "TSLA", -10))
