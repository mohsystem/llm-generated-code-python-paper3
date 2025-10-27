def buy_function(stock_name: str):
    """
    Simulates some secondary logic that runs after a stock purchase is recorded.
    
    :param stock_name: The name of the stock.
    """
    print(f"-> buy_function: Executing secondary logic for stock: {stock_name}")

def buy_stock(stock_name: str, quantity: int):
    """
    Simulates buying a stock and securely inserting the transaction into a database.
    This function demonstrates input validation and the use of parameterized queries
    to prevent SQL injection vulnerabilities.
    
    :param stock_name: The name of the stock to buy (e.g., "AAPL").
    :param quantity: The number of shares to buy.
    """
    # --- Security: Input Validation ---
    # 1. Ensure stock_name is a non-empty string.
    # 2. Ensure quantity is a positive integer.
    if not isinstance(stock_name, str) or not stock_name.strip():
        print("Error: Stock name must be a non-empty string.\n")
        return
    if not isinstance(quantity, int) or quantity <= 0:
        print("Error: Quantity must be a positive integer.\n")
        return

    print(f"Processing purchase of {quantity} shares of {stock_name}")

    # --- Security: Using Parameterized Queries ---
    # This is the standard way to prevent SQL injection. The database library
    # handles the safe substitution of parameters.
    
    # An insecure f-string format would be vulnerable:
    # query = f"INSERT INTO stocks (name, quantity) VALUES ('{stock_name}', {quantity})"
    
    # The secure, parameterized approach (simulated):
    print("Simulating secure database insertion...")
    # The '%s' are placeholders, not string formatting operators here.
    print("  Query Template: INSERT INTO stocks (name, quantity) VALUES (%s, %s)")
    print(f"  Binding parameters: ('{stock_name}', {quantity})")
    print("  Execution successful.")
    
    # Call the other function as required.
    buy_function(stock_name)
    print()  # Add a newline for cleaner test output.

if __name__ == "__main__":
    print("--- Running Python Test Cases ---\n")
    
    # Test Case 1: Valid input
    buy_stock("AAPL", 10)

    # Test Case 2: Another valid input
    buy_stock("GOOG", 5)

    # Test Case 3: Invalid quantity (negative)
    buy_stock("MSFT", -1)
    
    # Test Case 4: Invalid stock name (empty string)
    buy_stock("", 100)
    
    # Test Case 5: Invalid quantity type
    buy_stock("TSLA", "twenty")