
import sqlite3
import re
from typing import Optional, Dict

class Task137:
    DB_PATH = "products.db"
    PRODUCT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,50}$')
    
    def __init__(self):
        self.initialize_database()
    
    def initialize_database(self):
        """Initialize database with sample data"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("DROP TABLE IF EXISTS products")
            cursor.execute("""\n                CREATE TABLE products (\n                    id TEXT PRIMARY KEY,\n                    name TEXT NOT NULL,\n                    description TEXT,\n                    price REAL NOT NULL,\n                    stock INTEGER NOT NULL\n                )\n            """)
            
            products = [
                ("PROD001", "Laptop", "High-performance laptop", 999.99, 50),
                ("PROD002", "Mouse", "Wireless mouse", 29.99, 200),
                ("PROD003", "Keyboard", "Mechanical keyboard", 79.99, 150),
                ("PROD004", "Monitor", "27-inch 4K monitor", 399.99, 75),
                ("PROD005", "Headphones", "Noise-cancelling headphones", 199.99, 100)
            ]
            
            cursor.executemany(
                "INSERT INTO products (id, name, description, price, stock) VALUES (?, ?, ?, ?, ?)",
                products
            )
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    def validate_input(self, input_str: str) -> bool:
        """Validate input to prevent SQL injection"""
        if not input_str or not input_str.strip():
            return False
        return bool(self.PRODUCT_ID_PATTERN.match(input_str.strip()))
    
    def get_product_details(self, product_id: str) -> Optional[Dict]:
        """Query product details using parameterized query"""
        if not self.validate_input(product_id):
            print("Invalid product ID format. Please use alphanumeric characters, hyphens, or underscores only.")
            return None
        
        query = "SELECT id, name, description, price, stock FROM products WHERE id = ?"
        
        try:
            conn = sqlite3.connect(self.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute(query, (product_id,))
            result = cursor.fetchone()
            
            if result:
                product = {
                    'id': result[0],
                    'name': result[1],
                    'description': result[2],
                    'price': result[3],
                    'stock': result[4]
                }
                print("Product Found:")
                print(f"ID: {product['id']}")
                print(f"Name: {product['name']}")
                print(f"Description: {product['description']}")
                print(f"Price: ${product['price']}")
                print(f"Stock: {product['stock']}")
                conn.close()
                return product
            else:
                print(f"Product not found with ID: {product_id}")
                conn.close()
                return None
                
        except sqlite3.Error as e:
            print(f"Database query error: {e}")
            return None


if __name__ == "__main__":
    task = Task137()
    
    # Test cases
    print("Test Case 1: Valid product ID")
    task.get_product_details("PROD001")
    
    print("\\nTest Case 2: Valid product ID")
    task.get_product_details("PROD002")
    
    print("\\nTest Case 3: Non-existent product")
    task.get_product_details("PROD999")
    
    print("\\nTest Case 4: Invalid input (SQL injection attempt)")
    task.get_product_details("PROD001' OR '1'='1")
    
    print("\\nTest Case 5: Empty input")
    task.get_product_details("")
