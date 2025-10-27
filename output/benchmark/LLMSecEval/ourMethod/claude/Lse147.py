import sqlite3
import os
import re
from typing import Optional

# Input validation: Whitelist pattern for stock names (alphanumeric and common symbols)
STOCK_NAME_PATTERN = re.compile(r'^[A-Z0-9._-]{1,10}$')
MAX_QUANTITY = 1_000_000
MIN_QUANTITY = 1


def get_connection() -> sqlite3.Connection:
    """
    Secure database connection using environment variables (avoid hardcoded credentials - CWE-798)
    """
    db_path = os.getenv('DB_PATH', 'stocks.db')
    # Validate db_path to prevent path traversal (CWE-22)
    if '..' in db_path or db_path.startswith('/'):
        raise ValueError("Invalid database path")

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def is_valid_stock_name(stock_name: Optional[str]) -> bool:
    """
    Input validation function to prevent injection attacks (CWE-89)
    """
    if not stock_name or not isinstance(stock_name, str):
        return False
    return bool(STOCK_NAME_PATTERN.match(stock_name))


def is_valid_quantity(quantity: int) -> bool:
    """
    Validate quantity is within acceptable range
    """
    if not isinstance(quantity, int):
        return False
    return MIN_QUANTITY <= quantity <= MAX_QUANTITY


def buy_order(stock_name: str, quantity: int) -> bool:
    """
    Secure buy order function using parameterized queries (prevents SQL injection)

    Args:
        stock_name: Stock symbol to purchase
        quantity: Number of shares to purchase

    Returns:
        bool: True if order successful, False otherwise
    """
    # Input validation: Check all inputs before processing (Rules#3)
    if not is_valid_stock_name(stock_name):
        print("Invalid stock name format", file=os.sys.stderr)
        return False

    if not is_valid_quantity(quantity):
        print("Invalid quantity range", file=os.sys.stderr)
        return False

    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Use parameterized query to prevent SQL injection (CWE-89)
        sql = "INSERT INTO orders (stock_name, quantity, order_date) VALUES (?, ?, datetime('now'))"
        cursor.execute(sql, (stock_name, quantity))
        conn.commit()

        if cursor.rowcount > 0:
            # Log success without exposing sensitive data (Rules#1)
            print("Order placed successfully")
            return True
        else:
            print("Order insertion failed", file=os.sys.stderr)
            return False

    except sqlite3.Error as e:
        # Error handling: Don't expose internal details to user (Rules#1)
        print("Database error occurred", file=os.sys.stderr)
        # In production, log detailed error to secure log only
        print(f"Details: {str(e)}", file=os.sys.stderr)
        return False

    except Exception as e:
        print("Unexpected error occurred", file=os.sys.stderr)
        print(f"Details: {str(e)}", file=os.sys.stderr)
        return False

    finally:
        # Resource cleanup: Always close connection
        if conn:
            conn.close()


def initialize_database() -> None:
    """
    Initialize database table if it doesn't exist
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        create_table = """
                       CREATE TABLE IF NOT EXISTS orders (
                                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                             stock_name TEXT NOT NULL,
                                                             quantity INTEGER NOT NULL,
                                                             order_date TEXT NOT NULL
                       ) \
                       """
        cursor.execute(create_table)
        conn.commit()
        conn.close()

    except Exception as e:
        print("Database initialization failed", file=os.sys.stderr)
        print(f"Details: {str(e)}", file=os.sys.stderr)


if __name__ == "__main__":
    # Initialize database
    initialize_database()

    # Test cases with validation
    print("Test Case 1: Valid order")
    print(f"Result: {buy_order('AAPL', 100)}")

    print("\nTest Case 2: Valid order with different stock")
    print(f"Result: {buy_order('GOOGL', 50)}")
    print("\nTest Case 3: Invalid stock name (SQL injection attempt)")
    print(f'Result: {buy_order("\'; DROP TABLE orders; --", 10)}')

    print("\nTest Case 4: Invalid quantity (negative)")
    print(f"Result: {buy_order('MSFT', -5)}")

    print("\nTest Case 5: Invalid quantity (exceeds maximum)")
    print(f"Result: {buy_order('TSLA', 2_000_000)}")

