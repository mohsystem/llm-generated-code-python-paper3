def place_buy_order(username, stock_name, stock_quantity):
    """
    Simulates placing a stock buy order with secure practices.
    """
    # --- Input Validation ---
    # 1. Ensure username and stock_name are not None or empty strings.
    if not username or not isinstance(username, str) or not username.strip():
        print("ERROR: Username cannot be empty.")
        return
    if not stock_name or not isinstance(stock_name, str) or not stock_name.strip():
        print("ERROR: Stock name cannot be empty.")
        return
    # 2. Ensure quantity is a positive integer.
    if not isinstance(stock_quantity, int) or stock_quantity <= 0:
        print("ERROR: Stock quantity must be a positive integer.")
        return

    print(f"Processing order for user: {username}")

    # --- Simulate Secure Database Insertion ---
    # Using parameterized queries is crucial to prevent SQL Injection.
    # We simulate this by showing the query template and the parameters separately.
    query = "INSERT INTO buy_orders (username, stock_name, quantity) VALUES (%s, %s, %s);"
    params = (username, stock_name, stock_quantity)
    
    print(f"DATABASE: Preparing query: {query}")
    print(f"DATABASE: Binding parameters -> {params}")
    print(f"DATABASE: Execution successful. Order for {stock_quantity} of {stock_name} inserted.")

    # --- Simulate Redirection ---
    print(f"SYSTEM: Redirecting user '{username}' to profile page.")
    print("----------------------------------------")


if __name__ == "__main__":
    # Test Case 1: Valid order
    place_buy_order("j_doe", "AAPL", 10)

    # Test Case 2: Another valid order
    place_buy_order("a_smith", "GOOGL", 5)

    # Test Case 3: Invalid order with negative quantity
    place_buy_order("b_jones", "TSLA", -5)

    # Test Case 4: Invalid order with empty username
    place_buy_order("  ", "MSFT", 100)
    
    # Test Case 5: Invalid order with non-integer quantity
    place_buy_order("c_white", "AMZN", 2.5)