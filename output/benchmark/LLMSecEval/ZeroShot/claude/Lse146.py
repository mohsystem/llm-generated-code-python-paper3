
import sqlite3
import re
from datetime import datetime

def process_buy_order(username, stock_name, stock_quantity):
    """\n    Securely process a buy order and insert into database\n    """
    # Input validation
    if not username or not username.strip():
        print("Error: Username cannot be empty")
        return False
    
    if not stock_name or not stock_name.strip():
        print("Error: Stock name cannot be empty")
        return False
    
    if stock_quantity <= 0:
        print("Error: Stock quantity must be positive")
        return False
    
    # Sanitize inputs
    username = username.strip()
    stock_name = re.sub(r'[^a-zA-Z0-9]', '', stock_name.strip())
    
    try:
        # Connect to database (using SQLite for demonstration)
        conn = sqlite3.connect('trading.db')
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS buy_orders (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT NOT NULL,\n                stock_name TEXT NOT NULL,\n                stock_quantity INTEGER NOT NULL,\n                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        
        # Use parameterized query to prevent SQL injection
        cursor.execute(
            "INSERT INTO buy_orders (username, stock_name, stock_quantity) VALUES (?, ?, ?)",
            (username, stock_name, stock_quantity)
        )
        
        conn.commit()
        
        if cursor.rowcount > 0:
            print("Buy order placed successfully!")
            print("Redirecting to profile page...")
            return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()
    
    return False

if __name__ == "__main__":
    print("Testing Buy Order Processing System\\n")
    
    # Test case 1: Valid order
    print("Test 1: Valid buy order")
    process_buy_order("john_doe", "AAPL", 100)
    print()
    
    # Test case 2: Another valid order
    print("Test 2: Valid buy order for different stock")
    process_buy_order("jane_smith", "GOOGL", 50)
    print()
    
    # Test case 3: Invalid - empty username
    print("Test 3: Empty username (should fail)")
    process_buy_order("", "TSLA", 75)
    print()
    
    # Test case 4: Invalid - negative quantity
    print("Test 4: Negative quantity (should fail)")
    process_buy_order("bob_jones", "MSFT", -10)
    print()
    
    # Test case 5: Invalid - empty stock name
    print("Test 5: Empty stock name (should fail)")
    process_buy_order("alice_wilson", "", 200)
