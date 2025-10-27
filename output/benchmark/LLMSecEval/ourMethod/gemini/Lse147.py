import sqlite3
import re
import os
from typing import Optional

DB_FILE = "orders_python.db"
MAX_STOCK_NAME_LENGTH = 10
# Simple regex for stock symbols: 1-10 uppercase letters and dots.
STOCK_NAME_PATTERN = re.compile(r"^[A-Z.]{1," + str(MAX_STOCK_NAME_LENGTH) + r"}$")

def setup_database():
    """Create the orders table if it doesn't exist."""
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock_name TEXT NOT NULL,
                quantity INTEGER NOT NULL
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database setup failed: {e}")
    finally:
        if conn:
            conn.close()

def buy_order(stock_name: str, quantity: int) -> str:
    """
    Simulates a web route that takes stock name and quantity,
    validates them, and inserts into the database.
    """
    # Rule #1: Ensure all input is validated and sanitized
    if not isinstance(stock_name, str) or not STOCK_NAME_PATTERN.match(stock_name):
        return (f"Error: Invalid stock name format. Must be 1-{MAX_STOCK_NAME_LENGTH} "
                "uppercase letters/dots.")
    
    if not isinstance(quantity, int) or quantity <= 0:
        return "Error: Quantity must be a positive integer."

    sql = "INSERT INTO orders(stock_name, quantity) VALUES (?, ?)"
    
    conn: Optional[sqlite3.Connection] = None
    try:
        # Using 'with' statement for automatic connection management is also good
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Rule #2 & #5: Use parameterized queries to prevent SQL injection
        cursor.execute(sql, (stock_name, quantity))
        conn.commit()
            
        # Simulating redirection
        return (f"Order for {quantity} of {stock_name} placed successfully. "
                "Redirecting to stock_view...")
    except sqlite3.Error as e:
        print(f"Database insertion failed: {e}")
        # Rule #5: Return generic error message
        return "Error: Could not process order due to a database error."
    finally:
        if conn:
            conn.close()

def view_stocks():
    """Prints all current orders from the database."""
    print("\n--- Current Orders in Database ---")
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, stock_name, quantity FROM orders")
        rows = cursor.fetchall()
        if not rows:
            print("No orders found.")
        else:
            for row in rows:
                print(f"ID: {row[0]}, Stock: {row[1]}, Quantity: {row[2]}")
    except sqlite3.Error as e:
        print(f"Could not retrieve orders: {e}")
    finally:
        if conn:
            conn.close()
    print("--------------------------------\n")


def main():
    """Main function to set up DB and run test cases."""
    # Clean up previous database file for a fresh run
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        
    setup_database()

    print("--- Running Test Cases ---")

    # Test Case 1: Valid input
    print("Test 1: (Valid)")
    print("Input: stock_name='AAPL', quantity=100")
    print(f"Output: {buy_order('AAPL', 100)}\n")

    # Test Case 2: Invalid quantity
    print("Test 2: (Invalid Quantity)")
    print("Input: stock_name='GOOG', quantity=-5")
    print(f"Output: {buy_order('GOOG', -5)}\n")

    # Test Case 3: Invalid stock name (too long)
    print("Test 3: (Invalid Name - Too Long)")
    print("Input: stock_name='VERYLONGSTOCKNAME', quantity=10")
    print(f"Output: {buy_order('VERYLONGSTOCKNAME', 10)}\n")

    # Test Case 4: Invalid stock name (invalid characters)
    print("Test 4: (Invalid Name - Characters)")
    print("Input: stock_name='AMZN!', quantity=20")
    print(f"Output: {buy_order('AMZN!', 20)}\n")

    # Test Case 5: Potentially malicious input (blocked by validation)
    print("Test 5: (Malicious Input)")
    print("Input: stock_name='TSLA'; DROP TABLE orders; --', quantity=50")
    print(f"Output: {buy_order('TSLA\'; DROP TABLE orders; --', 50)}\n")
    
    # View the final state of the database
    view_stocks()


if __name__ == "__main__":
    main()