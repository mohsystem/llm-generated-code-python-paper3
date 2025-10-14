
import sqlite3
import re
import sys
import os
from typing import Optional
from dataclasses import dataclass

USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
MAX_USERNAME_LENGTH = 50

@dataclass
class Customer:
    username: str
    email: str
    full_name: str
    phone_number: str

    def __str__(self) -> str:
        return f"Customer(username='{self.username}', email='{self.email}', full_name='{self.full_name}', phone_number='{self.phone_number}')"

def validate_username(username: str) -> str:
    if username is None:
        raise ValueError("Username cannot be None")
    
    if not isinstance(username, str):
        raise TypeError("Username must be a string")
    
    trimmed = username.strip()
    
    if not trimmed:
        raise ValueError("Username cannot be empty")
    
    if len(trimmed) > MAX_USERNAME_LENGTH:
        raise ValueError(f"Username exceeds maximum length of {MAX_USERNAME_LENGTH}")
    
    if not USERNAME_PATTERN.match(trimmed):
        raise ValueError("Username contains invalid characters. Only alphanumeric and underscore allowed.")
    
    return trimmed

def get_customer_by_username(username: str, db_path: str) -> Optional[Customer]:
    validated_username = validate_username(username)
    
    query = "SELECT username, email, full_name, phone_number FROM customer WHERE username = ?"
    
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (validated_username,))
            row = cursor.fetchone()
            
            if row:
                return Customer(
                    username=row['username'],
                    email=row['email'],
                    full_name=row['full_name'],
                    phone_number=row['phone_number']
                )
    except sqlite3.Error as e:
        raise RuntimeError(f"Database error: {e}")
    
    return None

def setup_test_database(db_path: str) -> None:
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("DROP TABLE IF EXISTS customer")
            cursor.execute("""\n                CREATE TABLE customer (\n                    username TEXT PRIMARY KEY,\n                    email TEXT,\n                    full_name TEXT,\n                    phone_number TEXT\n                )\n            """)
            
            test_data = [
                ("testuser1", "user1@example.com", "John Doe", "555-0101"),
                ("testuser2", "user2@example.com", "Jane Smith", "555-0102"),
                ("testuser3", "user3@example.com", "Bob Johnson", "555-0103"),
                ("admin_user", "admin@example.com", "Admin User", "555-0100"),
                ("test_user_5", "user5@example.com", "Alice Williams", "555-0105")
            ]
            
            cursor.executemany(
                "INSERT INTO customer (username, email, full_name, phone_number) VALUES (?, ?, ?, ?)",
                test_data
            )
            
            conn.commit()
    except sqlite3.Error as e:
        raise RuntimeError(f"Database setup error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python solution.py <customerusername>", file=sys.stderr)
        sys.exit(1)
    
    username = sys.argv[1]
    
    db_path = os.environ.get('DB_PATH', ':memory:')
    
    try:
        setup_test_database(db_path)
        
        test_usernames = ["testuser1", "testuser2", "testuser3", "invalid@user", "testuser999"]
        
        for test_username in test_usernames:
            try:
                print(f"\\nQuerying for username: {test_username}")
                customer = get_customer_by_username(test_username, db_path)
                
                if customer:
                    print(f"Found: {customer}")
                else:
                    print("Customer not found")
            except ValueError as e:
                print(f"Validation error: {e}", file=sys.stderr)
            except RuntimeError as e:
                print(f"Error: {e}", file=sys.stderr)
                
    except RuntimeError as e:
        print(f"Database setup error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
