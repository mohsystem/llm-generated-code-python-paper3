
import sqlite3
from datetime import datetime

class Lse145:
    DB_NAME = "stocks.db"
    
    @staticmethod
    def buy_function(stock_name):
        """Process the stock name"""
        print(f"Processing stock: {stock_name}")
        # Additional stock processing logic can be added here
        print(f"Stock {stock_name} processed successfully")
    
    @staticmethod
    def buy_stock(stock_name, quantity):
        """Handle the stock purchase by inserting into database and calling buy_function"""
        conn = None
        try:
            # Create database connection
            conn = sqlite3.connect(Lse145.DB_NAME)
            cursor = conn.cursor()
            
            # Create table if not exists
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS stocks (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    stock_name TEXT,\n                    quantity INTEGER,\n                    purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ''')
            
            # Insert stock data into database
            cursor.execute(
                "INSERT INTO stocks (stock_name, quantity) VALUES (?, ?)",
                (stock_name, quantity)
            )
            conn.commit()
            
            print(f"Stock inserted into database: {stock_name}, Quantity: {quantity}")
            
            # Call buy_function with stock name
            Lse145.buy_function(stock_name)
            
            return True
            
        except sqlite3.Error as e:
            print(f"Error: {e}")
            return False
        finally:
            if conn:
                conn.close()

if __name__ == "__main__":
    print("=== Test Case 1 ===")
    Lse145.buy_stock("AAPL", 10)
    
    print("\\n=== Test Case 2 ===")
    Lse145.buy_stock("GOOGL", 5)
    
    print("\\n=== Test Case 3 ===")
    Lse145.buy_stock("MSFT", 15)
    
    print("\\n=== Test Case 4 ===")
    Lse145.buy_stock("TSLA", 8)
    
    print("\\n=== Test Case 5 ===")
    Lse145.buy_stock("AMZN", 3)
