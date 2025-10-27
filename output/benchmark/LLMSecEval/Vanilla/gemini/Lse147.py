# This dictionary simulates a database table for stocks.
# The key is the stock name (str), and the value is the quantity (int).
stock_database = {}

def buy_order(stock_name, quantity):
    """
    Simulates the buy_order route logic.
    It takes the stock name and quantity, inserts/updates it in the database,
    and simulates a redirect.
    In a real web framework like Flask or Django, this function would be
    a request handler.
    """
    print("\n--- Processing Buy Order ---")
    print(f"Received form data: stock_name='{stock_name}', quantity={quantity}")

    # Insert/Update logic for the database
    # If stock already exists, add to its quantity. Otherwise, add the new stock.
    if stock_name in stock_database:
        stock_database[stock_name] += quantity
    else:
        stock_database[stock_name] = quantity

    print(f"DATABASE: Successfully inserted/updated order for {stock_name} with quantity {quantity}.")
    print("ACTION: Redirecting user to the stock_view page...")

def stock_view():
    """
    Simulates the stock_view page by displaying all current holdings.
    """
    print("\n--- Displaying Stock View Page ---")
    print("Current Portfolio Holdings:")
    if not stock_database:
        print("Portfolio is empty.")
    else:
        for stock, quantity in stock_database.items():
            print(f"- Stock: {stock}, Quantity: {quantity}")
    print("---------------------------------")


def main():
    """
    Main function to run test cases.
    """
    print("Initialized a new stock portfolio (simulated database).")
    
    # --- 5 Test Cases ---

    # Test Case 1: Buy a new stock
    buy_order("AAPL", 10)

    # Test Case 2: Buy another new stock
    buy_order("GOOGL", 5)

    # Test Case 3: Buy more of an existing stock
    buy_order("AAPL", 15)

    # Test Case 4: Buy a stock with a different name
    buy_order("TSLA", 8)

    # Test Case 5: Buy a small quantity of another stock
    buy_order("MSFT", 2)

    # Display the final state of the portfolio, simulating the stock_view page
    stock_view()

if __name__ == "__main__":
    main()