
import sqlite3
from typing import List, Dict, Optional

class Task137:
    def __init__(self):
        self.conn = None
        
    def initialize_database(self) -> sqlite3.Connection:
        """Initialize in-memory database with sample data"""
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS products (\n                id INTEGER PRIMARY KEY,\n                name TEXT NOT NULL,\n                price REAL NOT NULL,\n                category TEXT NOT NULL\n            )\n        ''')
        
        sample_data = [
            (1, 'Laptop', 999.99, 'Electronics'),
            (2, 'Mouse', 29.99, 'Electronics'),
            (3, 'Desk Chair', 199.99, 'Furniture'),
            (4, 'Notebook', 4.99, 'Stationery'),
            (5, 'Monitor', 299.99, 'Electronics')
        ]
        
        cursor.executemany('INSERT INTO products VALUES (?, ?, ?, ?)', sample_data)
        conn.commit()
        
        self.conn = conn
        return conn
    
    def query_product_by_id(self, product_id: int) -> List[Dict]:
        """Query product by ID using parameterized query"""
        if self.conn is None:
            raise Exception("Database not initialized")
        
        cursor = self.conn.cursor()
        query = "SELECT * FROM products WHERE id = ?"
        
        cursor.execute(query, (product_id,))
        results = []
        
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'name': row[1],
                'price': row[2],
                'category': row[3]
            })
        
        return results
    
    def query_product_by_name(self, product_name: str) -> List[Dict]:
        """Query product by name using parameterized query"""
        if self.conn is None:
            raise Exception("Database not initialized")
        
        cursor = self.conn.cursor()
        query = "SELECT * FROM products WHERE name LIKE ?"
        
        cursor.execute(query, (f'%{product_name}%',))
        results = []
        
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'name': row[1],
                'price': row[2],
                'category': row[3]
            })
        
        return results
    
    def query_product_by_category(self, category: str) -> List[Dict]:
        """Query product by category using parameterized query"""
        if self.conn is None:
            raise Exception("Database not initialized")
        
        cursor = self.conn.cursor()
        query = "SELECT * FROM products WHERE category = ?"
        
        cursor.execute(query, (category,))
        results = []
        
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'name': row[1],
                'price': row[2],
                'category': row[3]
            })
        
        return results
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

if __name__ == "__main__":
    task = Task137()
    task.initialize_database()
    
    print("Test Case 1: Query product by ID = 1")
    result1 = task.query_product_by_id(1)
    for product in result1:
        print(product)
    
    print("\\nTest Case 2: Query product by name 'Mouse'")
    result2 = task.query_product_by_name("Mouse")
    for product in result2:
        print(product)
    
    print("\\nTest Case 3: Query products by category 'Electronics'")
    result3 = task.query_product_by_category("Electronics")
    for product in result3:
        print(product)
    
    print("\\nTest Case 4: Query product by partial name 'ote'")
    result4 = task.query_product_by_name("ote")
    for product in result4:
        print(product)
    
    print("\\nTest Case 5: Query non-existent product ID = 999")
    result5 = task.query_product_by_id(999)
    if not result5:
        print("No products found")
    else:
        for product in result5:
            print(product)
    
    task.close()
