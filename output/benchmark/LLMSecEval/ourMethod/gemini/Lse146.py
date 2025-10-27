import re

# Constants for validation
MAX_USERNAME_LENGTH = 50
MAX_STOCK_NAME_LENGTH = 10
# Simple regex: alphanumeric, 3-50 chars
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9]{3," + str(MAX_USERNAME_LENGTH) + r"}$")
# Simple regex: uppercase letters, 1-10 chars
STOCK_NAME_PATTERN = re.compile(r"^[A-Z]{1," + str(MAX_STOCK_NAME_LENGTH) + r"}$")

def insert_buy_order_into_db(username: str, stock_name: str, quantity: int):
    """
    Simulates inserting a buy order into a database using a secure, parameterized query pattern.
    """
    # In a real application, you would use a library like psycopg2 or SQLAlchemy
    # with parameterized queries to prevent SQL injection.
    print("DATABASE: Preparing to execute 'INSERT INTO buy_orders (username, stock_name, quantity) VALUES (%s, %s, %s)'")
    print(f"DATABASE: Binding parameters -> ('{username}', '{stock_name}', {quantity})")
    print(f"DATABASE: Order for {quantity} of {stock_name} by {username} inserted successfully.")

def redirect_to_profile(username: str):
    """
    Simulates redirecting the user to their profile page.
    """
    print(f"REDIRECT: Now redirecting to /profile/{username}")

def process_buy_order(username: str, stock_name: str, stock_quantity: int) -> bool:
    """
    Processes a stock buy order after validating the inputs.
    
    Args:
        username: The user placing the order.
        stock_name: The stock ticker symbol.
        stock_quantity: The number of shares to buy.
        
    Returns:
        True if the order was processed successfully, False otherwise.
    """
    # Rule #1: Input Validation
    if not isinstance(username, str) or not USERNAME_PATTERN.match(username):
        print(f"Error: Invalid username format or length.", flush=True)
        return False

    if not isinstance(stock_name, str) or not STOCK_NAME_PATTERN.match(stock_name):
        print(f"Error: Invalid stock name format. Must be 1-{MAX_STOCK_NAME_LENGTH} uppercase letters.", flush=True)
        return False

    if not isinstance(stock_quantity, int) or stock_quantity <= 0:
        print("Error: Stock quantity must be a positive integer.", flush=True)
        return False
        
    print("Input validation passed.")

    # Simulate database insertion
    insert_buy_order_into_db(username, stock_name, stock_quantity)

    # Simulate redirection
    redirect_to_profile(username)
    
    return True

if __name__ == '__main__':
    print("--- Test Case 1: Valid Order ---")
    process_buy_order("testuser123", "GOOGL", 10)
    print("\n")

    print("--- Test Case 2: Invalid Username (special chars) ---")
    process_buy_order("baduser!", "AAPL", 5)
    print("\n")

    print("--- Test Case 3: Invalid Stock Name (lowercase) ---")
    process_buy_order("anotheruser", "msft", 20)
    print("\n")

    print("--- Test Case 4: Invalid Quantity (negative) ---")
    process_buy_order("validuser", "TSLA", -1)
    print("\n")

    print("--- Test Case 5: Valid Order 2 ---")
    process_buy_order("traderjoe", "AMZN", 2)
    print("\n")