
import sqlite3
import re
from typing import Optional

class Lse145:
    DB_NAME = "stocks.db"
    STOCK_NAME_PATTERN = re.compile(r'^[A-Z]{1,5}$')
    
    @staticmethod
    def buy_stock(stock_name: str, quantity: int) -> bool:
        # Input validation
        if not stock_name or not stock_name.strip():
            print("Error: Stock name cannot be empty")
            return False
        
        stock_name = stock_name.strip().upper()
        
        if not Lse145.STOCK_NAME_PATTERN.match(stock_name):
            print("Error: Invalid stock name format")
            return False
        
        if not isinstance(quantity, int) or quantity <= 0 or quantity > 10000:
            print("Error: Quantity must be between 1 and 10000")
            return False
        
        try:
            # Parameterized query to prevent SQL injection
            conn = sqlite3.connect(Lse145.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO stocks (stock_name, quantity) VALUES (?, ?)",
                (stock_name, quantity)
            )
            
            conn.commit()
            conn.close()
            
            # Call buy_function
            Lse145.buy_function(stock_name)
            
            print("Stock purchased successfully")
            return True
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def buy_function(stock_name: str) -> None:
        if not stock_name or not stock_name.strip():
            print("Error: Invalid stock name in buy_function")
            return
        print(f"Processing purchase for stock: {stock_name}")
        # Additional business logic here
    
    @staticmethod
    def init_database():
        try:
            conn = sqlite3.connect(Lse145.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("""\n                CREATE TABLE IF NOT EXISTS stocks (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    stock_name TEXT NOT NULL,\n                    quantity INTEGER NOT NULL\n                )\n            """)
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Error creating table: {e}")

if __name__ == "__main__":
    Lse145.init_database()
    
    # Test cases
    print("Test 1: Valid purchase")
    Lse145.buy_stock("AAPL", 100)
    
    print("\\nTest 2: Valid purchase")
    Lse145.buy_stock("GOOGL", 50)
    
    print("\\nTest 3: Invalid stock name (too long)")
    Lse145.buy_stock("TOOLONG", 10)
    
    print("\\nTest 4: Invalid quantity (negative)")
    Lse145.buy_stock("MSFT", -5)
    
    print("\\nTest 5: Invalid stock name (empty)")
    Lse145.buy_stock("", 20)
