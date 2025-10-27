import re

# In-memory list to act as a simple database
database = []

def buy_order(stock_name, quantity):
    """
    Simulates buying a stock by validating input and adding it to an in-memory database.
    This function demonstrates secure coding practices like input validation.

    :param stock_name: The name of the stock (e.g., "AAPL"). Must be alphanumeric and not empty.
    :param quantity: The number of shares to buy. Must be a positive integer.
    :return: A string indicating the result of the operation.
    """
    # 1. Security: Validate stock name type and content
    if not isinstance(stock_name, str) or not stock_name.strip():
        return "Error: Stock name cannot be empty."
        
    # 2. Security: Sanitize stock name - ensure it contains only allowed characters.
    # This helps prevent injection attacks in a real database scenario.
    if not re.match("^[a-zA-Z0-9]+$", stock_name):
        return "Error: Stock name must be alphanumeric."

    # 3. Security: Validate quantity type and value
    if not isinstance(quantity, int) or quantity <= 0:
        return "Error: Quantity must be a positive integer."

    # 4. "Insert" into the database if all checks pass
    order = {"stock_name": stock_name, "quantity": quantity}
    database.append(order)

    # 5. Simulate redirection by returning a success message
    return f"SUCCESS: Order for {quantity} shares of {stock_name} placed. Redirecting to stock_view."

def main():
    """ Main function to run test cases """
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Valid order
    print(f"1. {buy_order('AAPL', 100)}")

    # Test Case 2: Invalid quantity (zero)
    print(f"2. {buy_order('GOOG', 0)}")

    # Test Case 3: Invalid stock name (contains special characters)
    print(f"3. {buy_order('MSFT-X', 50)}")

    # Test Case 4: Invalid stock name (empty)
    print(f"4. {buy_order('  ', 200)}")
    
    # Test Case 5: Valid order after some failures
    print(f"5. {buy_order('TSLA', 25)}")
    
    # --- Display Database Content ---
    print("\n--- Current Database State ---")
    if not database:
        print("Database is empty.")
    else:
        for i, order in enumerate(database, 1):
            print(f"Entry {i}: Stock={order['stock_name']}, Quantity={order['quantity']}")

if __name__ == "__main__":
    main()