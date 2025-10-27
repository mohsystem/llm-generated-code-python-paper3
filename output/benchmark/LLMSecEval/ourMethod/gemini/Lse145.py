import re
import sys

# Simulate a database table for stocks
stock_database = {}
MAX_STOCK_NAME_LENGTH = 16
# A regex to validate stock ticker format. Allows letters, numbers, dot, and hyphen.
STOCK_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+$")

def buy_function(stock_name: str):
    """
    A secondary function called by buy_stock.
    In a real application, this could perform logging or auditing.
    """
    # Input is considered sanitized as it comes from buy_stock
    print(f"[buy_function] INFO: Secondary processing for stock: {stock_name}")

def buy_stock(stock_name: str, quantity: int) -> bool:
    """
    Simulates buying a stock by validating input and adding it to an in-memory database.
    It calls a secondary function after a successful "purchase".
    
    :param stock_name: The name/ticker of the stock to buy.
    :param quantity: The amount of stock to buy.
    :return: True if the purchase was successful, False otherwise.
    """
    # Rule #1: Ensure all input is validated and sanitized
    # 1. Check type and for None or empty/whitespace-only string
    if not isinstance(stock_name, str) or not stock_name.strip():
        print("ERROR: Stock name must be a non-empty string.", file=sys.stderr)
        return False

    # 2. Trim the input
    sanitized_stock_name = stock_name.strip()

    # 3. Check length constraints
    if len(sanitized_stock_name) > MAX_STOCK_NAME_LENGTH:
        print(f"ERROR: Stock name exceeds maximum length of {MAX_STOCK_NAME_LENGTH} characters.", file=sys.stderr)
        return False
        
    # 4. Validate format/characters
    if not STOCK_NAME_PATTERN.match(sanitized_stock_name):
        print(f"ERROR: Stock name '{sanitized_stock_name}' contains invalid characters.", file=sys.stderr)
        return False

    # 5. Validate the quantity
    if not isinstance(quantity, int) or quantity <= 0:
        print("ERROR: Quantity must be a positive integer.", file=sys.stderr)
        return False

    # --- Processing ---
    print(f"SUCCESS: Validation passed for {quantity} shares of {sanitized_stock_name}.")
    
    # Simulate inserting/updating the record in the database
    current_quantity = stock_database.get(sanitized_stock_name, 0)
    stock_database[sanitized_stock_name] = current_quantity + quantity
    print(f"DATABASE: Portfolio now holds {stock_database[sanitized_stock_name]} shares of {sanitized_stock_name}.")
    
    # Call the secondary function
    buy_function(sanitized_stock_name)
    
    return True

def main():
    """Main function to run test cases."""
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Valid purchase
    print("\n--- Test Case 1: Valid Input ---")
    buy_stock("AAPL", 10)

    # Test Case 2: Invalid stock name (empty string)
    print("\n--- Test Case 2: Empty Stock Name ---")
    buy_stock("  ", 5)

    # Test Case 3: Invalid stock name (too long)
    print("\n--- Test Case 3: Stock Name Too Long ---")
    buy_stock("VERYLONGSTOCKNAMEISTOOLONG", 2)

    # Test Case 4: Invalid stock name (invalid characters)
    print("\n--- Test Case 4: Invalid Characters ---")
    buy_stock("GOOG<script>alert(1)</script>", 1)

    # Test Case 5: Invalid quantity (negative)
    print("\n--- Test Case 5: Invalid Quantity ---")
    buy_stock("MSFT", -5)
    
    print("\n--- Final Database State ---")
    print(stock_database)

if __name__ == "__main__":
    main()