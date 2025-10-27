# Simulating a database table with a list
orders_database = []

def place_buy_order(stock_name, stock_quantity, username):
    """
    Simulates inserting a buy order into the database.

    :param stock_name: The name of the stock to buy.
    :param stock_quantity: The quantity of the stock to buy.
    :param username: The user placing the order.
    :return: A confirmation message string.
    """
    # The stock name and quantity are stored in the variables.
    order = {
        'username': username,
        'stock_name': stock_name,
        'quantity': stock_quantity
    }

    # The buy order is inserted into the database.
    orders_database.append(order)
    print(f"DATABASE: Successfully inserted order for {username}")

    # The user is redirected to the profile page.
    print(f"SYSTEM: Redirecting user '{username}' to the profile page.")

    return f"Order for {stock_quantity} of {stock_name} has been placed successfully."

# In Python, the main execution block is typically structured like this.
# The Lse146 class name is not applicable in this procedural style.
if __name__ == "__main__":
    print("--- Running 5 Test Cases ---")

    # Test Case 1
    print("\n--- Test Case 1 ---")
    result1 = place_buy_order("AAPL", 10, "john_doe")
    print(f"RESULT: {result1}")

    # Test Case 2
    print("\n--- Test Case 2 ---")
    result2 = place_buy_order("GOOGL", 5, "jane_smith")
    print(f"RESULT: {result2}")

    # Test Case 3
    print("\n--- Test Case 3 ---")
    result3 = place_buy_order("TSLA", 20, "elon_fan")
    print(f"RESULT: {result3}")

    # Test Case 4
    print("\n--- Test Case 4 ---")
    result4 = place_buy_order("AMZN", 2, "john_doe")
    print(f"RESULT: {result4}")

    # Test Case 5
    print("\n--- Test Case 5 ---")
    result5 = place_buy_order("MSFT", 15, "bill_gates_fan")
    print(f"RESULT: {result5}")
    
    print("\n--- Final Database State ---")
    for order in orders_database:
        print(order)