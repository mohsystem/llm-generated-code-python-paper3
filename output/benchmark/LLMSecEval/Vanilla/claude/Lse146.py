
import sqlite3
from datetime import datetime

def buy_stock(username, stock_name, stock_quantity):
    """\n    Insert a buy order into the database and redirect to profile page\n    """
    conn = None
    cursor = None
    
    try:
        # Connect to database (using SQLite for portability)
        conn = sqlite3.connect('stock_db.db')
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS buy_orders (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT NOT NULL,\n                stock_name TEXT NOT NULL,\n                stock_quantity INTEGER NOT NULL,\n                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        
        # Insert buy order
        sql = "INSERT INTO buy_orders (username, stock_name, stock_quantity) VALUES (?, ?, ?)"
        cursor.execute(sql, (username, stock_name, stock_quantity))
        conn.commit()
        
        print(f"Buy order inserted successfully!")
        print(f"Redirecting to profile page...")
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    buy_stock("john_doe", "AAPL", 10)
    
    print("\\nTest Case 2:")
    buy_stock("jane_smith", "GOOGL", 5)
    
    print("\\nTest Case 3:")
    buy_stock("bob_jones", "MSFT", 15)
    
    print("\\nTest Case 4:")
    buy_stock("alice_williams", "TSLA", 20)
    
    print("\\nTest Case 5:")
    buy_stock("charlie_brown", "AMZN", 8)
