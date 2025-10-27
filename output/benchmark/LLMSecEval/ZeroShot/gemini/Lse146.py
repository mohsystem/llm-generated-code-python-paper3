import re

# This is a simulation. No actual database connection is made.
# The code demonstrates the secure use of parameterized queries to prevent SQL injection.

def buy_stock(username: str, stock_name: str, stock_quantity: int) -> str:
    """
    Securely inserts a buy order into the database using parameterized queries.
    This prevents SQL injection attacks.

    :param username: The user placing the order.
    :param stock_name: The name of the stock.
    :param stock_quantity: The quantity of the stock to buy.
    :return: A string indicating the result of the operation.
    """
    # 1. Input Validation
    # Basic validation for stock names (alphanumeric, dot, dash)
    if not re.match(r"^[a-zA-Z0-9.-]+$", stock_name):
        return "Error: Invalid stock name format."
    # Basic validation for usernames
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        return "Error: Invalid username format."
    if not isinstance(stock_quantity, int) or stock_quantity <= 0:
        return "Error: Stock quantity must be a positive integer."

    # 2. Use Parameterized Queries for security
    # The '?' (or '%s' for some DB drivers) is a placeholder.
    # The database driver will safely substitute the values, preventing injection.
    sql = "INSERT INTO buy_orders (username, stock_name, quantity, order_date) VALUES (?, ?, ?, CURRENT_TIMESTAMP);"
    params = (username, stock_name, stock_quantity)

    print("\n--- New Order ---")
    print("Executing secure buy order...")
    print(f"Username: {username}")
    print(f"Stock: {stock_name}")
    print(f"Quantity: {stock_quantity}")

    # In a real application, you would use a database library like sqlite3 or psycopg2
    # and its execute method with parameters.
    #
    # import sqlite3
    # conn = sqlite3.connect('stocks.db')
    # cursor = conn.cursor()
    # try:
    #     cursor.execute(sql, params)
    #     conn.commit()
    #     return f"Success: Order placed for {username}. Redirecting to profile page."
    # except sqlite3.Error as e:
    #     conn.rollback()
    #     return f"Error: A database error occurred: {e}"
    # finally:
    #     conn.close()

    # Simulation of the parameterized query execution
    print("Simulating parameterized query execution...")
    print(f"SQL Template: {sql}")
    print(f"Parameters to bind: {params}")
    print("Simulation successful.")

    return f"Success: Order placed for {username}. Redirecting to profile page."

def main():
    """Main function with 5 test cases."""
    # Test Case 1: Normal valid transaction
    print(buy_stock("jdoe", "GOOGL", 10))

    # Test Case 2: Another valid transaction
    print(buy_stock("asmith", "TSLA", 5))

    # Test Case 3: SQL Injection attempt (should be handled safely as a literal string)
    print(buy_stock("evil_user", "FAKE.STK'); DROP TABLE buy_orders; --", 1))

    # Test Case 4: Invalid quantity
    print(buy_stock("jdoe", "MSFT", -50))

    # Test Case 5: Invalid username
    print(buy_stock("bad user!", "AAPL", 100))

if __name__ == "__main__":
    main()