
import sqlite3
import re
from datetime import datetime

DB_NAME = 'stocks.db'
STOCK_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,50}$')

def initialize_database():
    """Initialize the database with orders table"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS orders (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                stock_name TEXT NOT NULL,\n                quantity INTEGER NOT NULL,\n                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        conn.commit()
        conn.close()
    except sqlite3.Error:
        print("Database initialization error")

def validate_stock_name(stock_name):
    """Validate stock name format"""
    return stock_name and STOCK_NAME_PATTERN.match(stock_name) is not None

def validate_quantity(quantity):
    """Validate quantity is positive integer"""
    try:
        qty = int(quantity)
        return qty > 0
    except (ValueError, TypeError):
        return False

def buy_order(stock_name, quantity):
    """Insert buy order into database with input validation"""
    # Input validation
    if not validate_stock_name(stock_name):
        print("Error: Invalid stock name format")
        return False
    
    if not validate_quantity(quantity):
        print("Error: Quantity must be positive integer")
        return False
    
    # Insert into database using parameterized query
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Parameterized query prevents SQL injection
        cursor.execute(
            "INSERT INTO orders (stock_name, quantity) VALUES (?, ?)",
            (stock_name, int(quantity))
        )
        
        conn.commit()
        conn.close()
        
        print(f"Order placed successfully: {stock_name} x {quantity}")
        return True
        
    except sqlite3.Error:
        print("Error placing order")
        return False

def stock_view():
    """Display all orders from database"""
    print("\\n=== Stock View ===")
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, stock_name, quantity, order_date FROM orders")
        rows = cursor.fetchall()
        
        for row in rows:
            print(f"ID: {row[0]}, Stock: {row[1]}, Quantity: {row[2]}, Date: {row[3]}")
        
        conn.close()
        
    except sqlite3.Error:
        print("Error retrieving orders")

if __name__ == "__main__":
    # Initialize database
    initialize_database()
    
    # Test cases
    print("Test Case 1:")
    buy_order("AAPL", 10)
    
    print("\\nTest Case 2:")
    buy_order("GOOGL", 5)
    
    print("\\nTest Case 3:")
    buy_order("MSFT", 15)
    
    print("\\nTest Case 4 (Invalid - negative quantity):")
    buy_order("TSLA", -5)
    
    print("\\nTest Case 5 (Invalid - SQL injection attempt):")
    buy_order("AAPL'; DROP TABLE orders;--", 10)
    
    # Display all orders
    stock_view()
