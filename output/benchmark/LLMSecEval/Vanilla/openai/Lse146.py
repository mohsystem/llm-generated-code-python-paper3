# Single-file program with in-memory "database"

DATABASE = []

def process_buy_order(stock_name, stock_quantity, username):
    order = {
        "username": username,
        "stock_name": stock_name,
        "stock_quantity": stock_quantity,
    }
    DATABASE.append(order)
    return f"/users/{username}/profile"

if __name__ == "__main__":
    print(process_buy_order("AAPL", 10, "alice"))
    print(process_buy_order("GOOGL", 5, "bob"))
    print(process_buy_order("TSLA", 2, "alice"))
    print(process_buy_order("MSFT", 100, "carol"))
    print(process_buy_order("AMZN", 7, "dave"))