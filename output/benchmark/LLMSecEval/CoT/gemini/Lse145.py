# Simulating a database table for stock portfolio using a dictionary
portfolio = {}

def buy_function(stock_name):
    """
    This function is called by buy_stock to perform a subsequent action.
    In a real application, this could be logging, sending a notification, etc.
    
    Args:
        stock_name (str): The name of the stock that was purchased.
    """
    print(f"LOG: Post-purchase action for {stock_name} completed.")

def buy_stock(stock_name, quantity):
    """
    Simulates buying a stock. It takes the stock name and quantity,
    validates the input, "inserts" it into the simulated database,
    and then calls a subsequent function.

    Args:
        stock_name (str): The ticker symbol of the stock to buy (e.g., "AAPL").
        quantity (int): The number of shares to buy.
    """
    print(f"\nAttempting to buy {quantity} of {stock_name}...")

    # --- Security: Input Validation ---
    # 1. Ensure stock_name is not None or just whitespace.
    # 2. Ensure quantity is a positive number.
    if not stock_name or not stock_name.strip():
        print("Error: Stock name cannot be empty.")
        return
    
    # Ensure quantity is of integer type before comparison
    if not isinstance(quantity, int) or quantity <= 0:
        print("Error: Quantity must be a positive integer.")
        return

    # Sanitize input
    sanitized_stock_name = stock_name.strip().upper()

    print(f"Inserting {quantity} of {sanitized_stock_name} into the database.")
    
    # --- "Database" Insertion ---
    # In a real application, this would use parameterized queries to prevent SQL injection.
    # Example (with a library like psycopg2 for PostgreSQL):
    # cursor.execute(
    #     "INSERT INTO portfolio (stock_name, quantity) VALUES (%s, %s) "
    #     "ON CONFLICT (stock_name) DO UPDATE SET quantity = portfolio.quantity + %s;",
    #     (sanitized_stock_name, quantity, quantity)
    # )
    # connection.commit()

    # Simulating the database update
    current_quantity = portfolio.get(sanitized_stock_name, 0)
    portfolio[sanitized_stock_name] = current_quantity + quantity
    print(f"Successfully updated portfolio for {sanitized_stock_name}.")
    
    # Call the subsequent function as per the prompt
    buy_function(sanitized_stock_name)


if __name__ == "__main__":
    print("--- Starting Stock Purchase Simulation ---")

    # Test Case 1: Buy a new stock
    buy_stock("GOOG", 10)

    # Test Case 2: Buy more of an existing stock
    buy_stock("GOOG", 5)

    # Test Case 3: Buy another new stock
    buy_stock("MSFT", 20)

    # Test Case 4: Invalid quantity
    buy_stock("TSLA", 0)

    # Test Case 5: Invalid stock name
    buy_stock(None, 100)
    
    print("\n--- Final Portfolio Status ---")
    if not portfolio:
        print("Portfolio is empty.")
    else:
        for stock, quantity in portfolio.items():
            print(f"Stock: {stock}, Quantity: {quantity}")