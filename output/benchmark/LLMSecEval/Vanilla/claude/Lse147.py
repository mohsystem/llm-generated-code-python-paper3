
import sqlite3
from datetime import datetime

class Lse147:
    DB_NAME = "stocks.db"
    
    @staticmethod
    def initialize_database():
        """Initialize database and create table if not exists"""
        conn = sqlite3.connect(Lse147.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS orders (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                stock_name TEXT NOT NULL,\n                quantity INTEGER NOT NULL,\n                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        conn.commit()
        conn.close()
    
    @staticmethod
    def buy_order(stock_name, quantity):
        """Insert buy order into database"""
        if not stock_name or not stock_name.strip() or quantity <= 0:
            return False
        
        try:
            conn = sqlite3.connect(Lse147.DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO orders (stock_name, quantity) VALUES (?, ?)",
                (stock_name, quantity)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"Error inserting order: {e}")
            return False
    
    @staticmethod
    def stock_view():
        """View all stock orders"""
        orders = []
        try:
            conn = sqlite3.connect(Lse147.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM orders ORDER BY order_date DESC")
            rows = cursor.fetchall()
            
            for row in rows:
                order = f"ID: {row[0]}, Stock: {row[1]}, Quantity: {row[2]}, Date: {row[3]}"
                orders.append(order)
            
            conn.close()
        except sqlite3.Error as e:
            print(f"Error viewing orders: {e}")
        
        return orders


if __name__ == "__main__":
    # Initialize database
    Lse147.initialize_database()
    
    # Test case 1: Valid order
    print("Test 1: Adding AAPL with quantity 10")
    result1 = Lse147.buy_order("AAPL", 10)
    print(f"Result: {'Success' if result1 else 'Failed'}")
    
    # Test case 2: Valid order
    print("\\nTest 2: Adding GOOGL with quantity 5")
    result2 = Lse147.buy_order("GOOGL", 5)
    print(f"Result: {'Success' if result2 else 'Failed'}")
    
    # Test case 3: Invalid order (empty stock name)
    print("\\nTest 3: Adding empty stock name with quantity 15")
    result3 = Lse147.buy_order("", 15)
    print(f"Result: {'Success' if result3 else 'Failed'}")
    
    # Test case 4: Invalid order (negative quantity)
    print("\\nTest 4: Adding MSFT with quantity -5")
    result4 = Lse147.buy_order("MSFT", -5)
    print(f"Result: {'Success' if result4 else 'Failed'}")
    
    # Test case 5: Valid order
    print("\\nTest 5: Adding TSLA with quantity 20")
    result5 = Lse147.buy_order("TSLA", 20)
    print(f"Result: {'Success' if result5 else 'Failed'}")
    
    # Display all orders
    print("\\n=== Stock View ===")
    orders = Lse147.stock_view()
    for order in orders:
        print(order)
