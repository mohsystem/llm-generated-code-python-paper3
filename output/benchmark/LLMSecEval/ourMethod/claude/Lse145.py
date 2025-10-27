
import sqlite3
import re
import os
from datetime import datetime
from typing import Optional

# Constants for validation
MAX_STOCK_NAME_LENGTH = 50
MAX_QUANTITY = 1000000
MIN_QUANTITY = 1
def get_secure_connection() -> Optional[sqlite3.Connection]:
    """
    Establishes a secure database connection using credentials from environment variables.
    Never hardcode database credentials in code.
    """
    try:
        # Get database path from environment variable
        db_path = os.environ.get('DB_PATH', 'stocks.db')

        # Validate database path to prevent path traversal
        # Normalize path and ensure it doesn't contain traversal sequences
        db_path = os.path.normpath(db_path)
        if '..' in db_path or db_path.startswith('/'):
            raise ValueError("Invalid database path")

        # Create connection with secure settings
        conn = sqlite3.connect(db_path, isolation_level='DEFERRED')

        # Enable foreign keys for referential integrity
        conn.execute("PRAGMA foreign_keys = ON")

        return conn

    except Exception as e:
        # Log detailed error to secure log, don't expose to user
        print(f"Database connection error: {str(e)}", file=sys.stderr)
        return None

def is_valid_stock_name(stock_name: str) -> bool:
    """\n    Validates stock name input to prevent injection attacks and ensure data integrity.\n    Treats all input as untrusted.\n    """
    # Check for None or empty string
    if not stock_name or not stock_name.strip():
        return False
    
    # Check length to prevent buffer issues
    if len(stock_name) > MAX_STOCK_NAME_LENGTH:
        return False
    
    # Allow only alphanumeric characters, spaces, hyphens, and underscores
    # This prevents SQL injection, command injection, and path traversal
    if not re.match(r'^[a-zA-Z0-9\\s_-]+$', stock_name):
        return False
    
    return True

def is_valid_quantity(quantity: int) -> bool:
    """\n    Validates quantity to prevent integer overflow and business logic errors.\n    """
    try:
        # Ensure it's an integer type\n        quantity = int(quantity)\n        \n        # Check bounds\n        if quantity < MIN_QUANTITY or quantity > MAX_QUANTITY:\n            return False\n        \n        return True\n    except (ValueError, TypeError):\n        return False\n\ndef buy_function(stock_name: str) -> str:\n    """\n    Processes the stock name with security validation.\n    All inputs are treated as untrusted and validated.\n    """\n    # Input validation - reject invalid input early\n    if not is_valid_stock_name(stock_name):\n        return "Invalid stock name"\n    \n    # Sanitize by removing extra whitespace\n    sanitized_name = stock_name.strip()\n    \n    # Business logic processing\n    return f"Processing purchase for stock: {sanitized_name}"\n\ndef buy_stock(stock_name: str, quantity: int) -> str:\n    """\n    Main function to handle stock purchase when buy button is clicked.\n    Validates inputs, calls buy_function, and inserts data into database using parameterized query.\n    """\n    conn = None\n    cursor = None\n    \n    try:\n        # Input validation - fail closed on invalid input\n        if not is_valid_stock_name(stock_name):\n            return "Error: Invalid stock name format"\n        \n        if not is_valid_quantity(quantity):\n            return f"Error: Invalid quantity. Must be between {MIN_QUANTITY} and {MAX_QUANTITY}"\n        \n        # Sanitize inputs\n        sanitized_name = stock_name.strip()\n        \n        # Call buy_function to process the stock\n        buy_result = buy_function(sanitized_name)\n        \n        # Get secure database connection\n        conn = get_secure_connection()\n        if conn is None:\n            return "Error: Unable to establish database connection"\n        \n        cursor = conn.cursor()\n        \n        # Use parameterized query to prevent SQL injection\n        # Never concatenate user input into SQL queries\n        sql = "INSERT INTO stock_purchases (stock_name, quantity, purchase_date) VALUES (?, ?, ?)"\n        \n        # Execute with parameters - database driver handles escaping\n        cursor.execute(sql, (sanitized_name, quantity, datetime.now().isoformat()))\n        \n        # Commit transaction\n        conn.commit()\n        \n        if cursor.rowcount > 0:\n            return f"Stock purchase successful: {buy_result}"\n        else:\n            return "Stock purchase failed"\n            \n    except sqlite3.Error as e:\n        # Log detailed error to secure log only\n        print(f"Database error: {str(e)}", file=sys.stderr)\n        # Return generic error to user - don't leak internal details
        return "Error: Unable to complete purchase"
    except Exception as e:
        # Catch any other exceptions
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        return "Error: Unable to complete purchase"
    finally:
        # Clean up resources to prevent leaks
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Test cases
if __name__ == "__main__":
    # Create test database table
    import sys
    
    print("Test Case 1 - Valid stock purchase:")
    print(buy_stock("AAPL", 10))
    
    print("\\nTest Case 2 - Valid stock with hyphen:")
    print(buy_stock("TECH-CORP", 50))
    
    print("\\nTest Case 3 - Invalid stock name (SQL injection attempt):")
    print(buy_stock("AAPL'; DROP TABLE stock_purchases; --", 10))
    
    print("\\nTest Case 4 - Invalid quantity (negative):")
    print(buy_stock("GOOGL", -5))
    
    print("\\nTest Case 5 - Invalid quantity (too large):")
    print(buy_stock("MSFT", 2000000))
