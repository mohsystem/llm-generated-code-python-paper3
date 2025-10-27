
import sqlite3
import re
from datetime import datetime

class Lse147:
    DB_NAME = "stocks.db"
    
    @staticmethod
    def initialize_database():
        """Initialize database and create table if not exists"""
        try:
            conn = sqlite3.connect(Lse147.DB_NAME)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS orders (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    stock_name TEXT NOT NULL,\n                    quantity INTEGER NOT NULL,\n                    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    @staticmethod
    def buy_order(stock_name, quantity):
        """Secure method to insert buy order using parameterized queries"""
        # Input validation
        if not stock_name or not stock_name.strip():
            print("Error: Stock name cannot be empty")
            return False
        
        if not isinstance(quantity, int) or quantity <= 0:
            print("Error: Quantity must be a positive integer")
            return False
        
        # Sanitize stock name (allow only alphanumeric and common stock symbols)
        if not re.match(r'^[a-zA-Z0-9._-]+$', stock_name):
            print("Error: Invalid stock name format")
            return False
        
        try:
            conn = sqlite3.connect(Lse147.DB_NAME)
            cursor = conn.cursor()
            
            # Using parameterized query to prevent SQL injection
            cursor.execute(
                "INSERT INTO orders (stock_name, quantity) VALUES (?, ?)",
                (stock_name.strip(), quantity)
            )
            
            conn.commit()
            conn.close()
            print("Order placed successfully!")
            return True
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def stock_view():
        """Method to view all stock orders"""
        try:
            conn = sqlite3.connect(Lse147.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT id, stock_name, quantity, order_date FROM orders ORDER BY order_date DESC"
            )
            
            orders = cursor.fetchall()
            conn.close()
            
            print("\\n=== Stock Orders ===")
            print(f"{'ID':<5} {'Stock Name':<15} {'Quantity':<10} {'Order Date':<20}")
            print("-" * 55)
            
            for order in orders:
                print(f"{order[0]:<5} {order[1]:<15} {order[2]:<10} {order[3]:<20}")
                
        except sqlite3.Error as e:
            print(f"Error viewing orders: {e}")


if __name__ == "__main__":
    Lse147.initialize_database()
    
    # Test cases
    print("Running test cases...\\n")
    
    # Test case 1: Valid order
    print("Test 1: Valid order")
    Lse147.buy_order("AAPL", 100)
    
    # Test case 2: Valid order with different stock
    print("\\nTest 2: Another valid order")
    Lse147.buy_order("GOOGL", 50)
    
    # Test case 3: Invalid - empty stock name
    print("\\nTest 3: Empty stock name")
    Lse147.buy_order("", 25)
    
    # Test case 4: Invalid - negative quantity
    print("\\nTest 4: Negative quantity")
    Lse147.buy_order("MSFT", -10)
    
    # Test case 5: Invalid - special characters in stock name
    print("\\nTest 5: Invalid stock name with SQL injection attempt")
    Lse147.buy_order("TSLA'; DROP TABLE orders; --", 75)
    
    # Display all orders
    Lse147.stock_view()
