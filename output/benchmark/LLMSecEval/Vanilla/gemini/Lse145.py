# Simulating a database table for stock holdings
portfolio = {}

def buy_function(stock_name):
    """
    This function is called by buy_stock to perform additional processing.
    It takes the stock name as an argument.
    """
    print(f"-> buy_function: Performing additional checks/logging for {stock_name}...")

def buy_stock(stock_name, quantity):
    """
    Simulates buying a stock and inserting it into a database.
    This function takes the stock name and quantity and updates the portfolio.
    It then calls the buy_function.
    """
    print(f"Attempting to buy {quantity} shares of {stock_name}.")
    
    # Simulate inserting/updating the database
    if stock_name in portfolio:
        portfolio[stock_name] += quantity
    else:
        portfolio[stock_name] = quantity
        
    print(f"   Database updated: Portfolio now holds {portfolio[stock_name]} shares of {stock_name}.")
    
    # Call the other function as per requirement
    buy_function(stock_name)
    print() # for better readability of test cases

def main():
    """ Main function with 5 test cases """
    print("--- Running 5 Test Cases ---")
    
    # Test Case 1
    buy_stock("AAPL", 10)
    
    # Test Case 2
    buy_stock("GOOGL", 5)
    
    # Test Case 3
    buy_stock("MSFT", 20)
    
    # Test Case 4: Buying more of an existing stock
    buy_stock("AAPL", 15)
    
    # Test Case 5
    buy_stock("AMZN", 2)
    
    print("--- Final Portfolio State ---")
    for stock, qty in portfolio.items():
        print(f"{stock}: {qty}")

if __name__ == "__main__":
    main()