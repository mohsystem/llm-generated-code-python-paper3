
import sqlite3
import re
from typing import Optional, Tuple
from dataclasses import dataclass

PRODUCT_ID_PATTERN = re.compile(r'^[A-Za-z0-9_-]{1,50}$')
MAX_INPUT_LENGTH = 50


@dataclass
class ProductDetails:
    id: str
    name: str
    price: float
    description: str
    
    def __str__(self) -> str:
        return f"Product[id={self.id}, name={self.name}, price={self.price:.2f}, description={self.description}]"


def validate_product_id(input_str: str) -> str:
    if input_str is None:
        raise ValueError("Product ID cannot be None")
    
    if not isinstance(input_str, str):
        raise ValueError("Product ID must be a string")
    
    if len(input_str) > MAX_INPUT_LENGTH:
        raise ValueError("Product ID exceeds maximum length")
    
    if not PRODUCT_ID_PATTERN.match(input_str):
        raise ValueError("Product ID contains invalid characters")
    
    return input_str


def query_product(product_id: str, conn: sqlite3.Connection) -> Optional[ProductDetails]:
    validated_id = validate_product_id(product_id)
    
    query = "SELECT id, name, price, description FROM products WHERE id = ?"
    
    cursor = conn.cursor()
    cursor.execute(query, (validated_id,))
    
    row = cursor.fetchone()
    cursor.close()
    
    if row:
        return ProductDetails(
            id=row[0],
            name=row[1],
            price=row[2],
            description=row[3]
        )
    
    return None


def create_in_memory_database() -> sqlite3.Connection:
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    cursor.execute('''\n        CREATE TABLE IF NOT EXISTS products (\n            id TEXT PRIMARY KEY,\n            name TEXT NOT NULL,\n            price REAL NOT NULL,\n            description TEXT\n        )\n    ''')
    
    products = [
        ('P001', 'Laptop', 999.99, 'High-performance laptop'),
        ('P002', 'Mouse', 29.99, 'Wireless mouse'),
        ('P003', 'Keyboard', 79.99, 'Mechanical keyboard'),
        ('P004', 'Monitor', 299.99, '27-inch monitor'),
        ('P005', 'Headphones', 149.99, 'Noise-canceling headphones')
    ]
    
    cursor.executemany('INSERT INTO products VALUES (?, ?, ?, ?)', products)
    conn.commit()
    cursor.close()
    
    return conn


def main():
    conn = create_in_memory_database()
    
    try:
        print("Test Case 1: Valid product ID")
        product1 = query_product("P001", conn)
        print(product1 if product1 else "Product not found")
        
        print("\\nTest Case 2: Another valid product ID")
        product2 = query_product("P003", conn)
        print(product2 if product2 else "Product not found")
        
        print("\\nTest Case 3: Non-existent product")
        product3 = query_product("P999", conn)
        print(product3 if product3 else "Product not found")
        
        print("\\nTest Case 4: Invalid characters (SQL injection attempt)")
        try:
            product4 = query_product("P001' OR '1'='1", conn)
            print(product4 if product4 else "Product not found")
        except ValueError as e:
            print(f"Validation error: {e}")
        
        print("\\nTest Case 5: Input too long")
        try:
            long_id = "P" * 100
            product5 = query_product(long_id, conn)
            print(product5 if product5 else "Product not found")
        except ValueError as e:
            print(f"Validation error: {e}")
            
    finally:
        conn.close()


if __name__ == "__main__":
    main()
