
import sqlite3
import re
from datetime import datetime

class Lse145:
    DB_NAME = "stocks.db"
    
    @staticmethod
    def init_database():
        """Initialize the database and create table if not exists"""
        try:
            conn = sqlite3.connect(Lse145.DB_NAME)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS stocks (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    stock_name TEXT NOT NULL,\n                    quantity INTEGER NOT NULL,\n                    purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    @staticmethod
    def buy_function(stock_name):
        """Helper function called after buying stock"""
        if not stock_name or not stock_name.strip():
            print("Invalid stock name")
            return False
        
        # Sanitize stock name
        stock_name = re.sub(r'[^a-zA-Z0-9]', '', stock_name.strip())
        
        print(f"Processing purchase for stock: {stock_name}")
        # Additional business logic can be added here
        return True
    
    @staticmethod
    def buy_stock(stock_name, quantity):
        """Main function to buy stock - secure implementation"""
        # Input validation
        if not stock_name or not stock_name.strip():
            print("Error: Stock name cannot be empty")
            return False
        
        if not isinstance(quantity, int) or quantity <= 0:
            print("Error: Quantity must be a positive integer")
            return False
        
        # Sanitize input
        stock_name = re.sub(r'[^a-zA-Z0-9]', '', stock_name.strip())
        
        # Call buy_function
        if not Lse145.buy_function(stock_name):
            return False
        
        # Insert into database using parameterized query (prevents SQL injection)
        try:
            conn = sqlite3.connect(Lse145.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO stocks(stock_name, quantity) VALUES(?, ?)",
                (stock_name, quantity)
            )
            
            conn.commit()
            
            if cursor.rowcount > 0:
                print(f"Successfully purchased {quantity} shares of {stock_name}")
                conn.close()
                return True
            
            conn.close()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        
        return False

# Main execution with test cases
if __name__ == "__main__":
    Lse145.init_database()
    
    print("=== Test Case 1: Valid purchase ===")
    Lse145.buy_stock("AAPL", 10)
    
    print("\\n=== Test Case 2: Another valid purchase ===")
    Lse145.buy_stock("GOOGL", 5)
    
    print("\\n=== Test Case 3: Invalid quantity (negative) ===")
    Lse145.buy_stock("MSFT", -5)
    
    print("\\n=== Test Case 4: Invalid quantity (zero) ===")
    Lse145.buy_stock("TSLA", 0)
    
    print("\\n=== Test Case 5: Empty stock name ===")
    Lse145.buy_stock("", 10)
