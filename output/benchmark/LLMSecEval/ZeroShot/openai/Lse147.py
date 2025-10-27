import sqlite3

def _is_valid_stock_name(name: str) -> bool:
    if name is None:
        return False
    trimmed = name.strip()
    if not trimmed or len(trimmed) > 50:
        return False
    for ch in trimmed:
        if not (ch.isalnum() or ch in " ._-"):
            return False
    return True

def init_db(db_path: str) -> bool:
    ddl = """
    CREATE TABLE IF NOT EXISTS buy_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stock_name TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        conn = sqlite3.connect(db_path)
        with conn:
            conn.execute(ddl)
        conn.close()
        return True
    except sqlite3.Error:
        return False

# Simulates the buy_order route: validates input, inserts into DB securely, returns redirect path or error message.
def buy_order(db_path: str, stock_name: str, quantity: int) -> str:
    if not _is_valid_stock_name(stock_name):
        return "ERROR: Invalid stock name"
    if not isinstance(quantity, int) or quantity <= 0 or quantity > 1_000_000:
        return "ERROR: Invalid quantity"

    try:
        conn = sqlite3.connect(db_path)
        with conn:
            conn.execute(
                "INSERT INTO buy_orders (stock_name, quantity) VALUES (?, ?)",
                (stock_name.strip(), int(quantity)),
            )
        conn.close()
        return "/stock_view"
    except sqlite3.Error:
        return "ERROR: Database failure"

if __name__ == "__main__":
    dbp = "python_buy_orders.db"
    print("Init DB:", init_db(dbp))

    # 5 test cases
    print(buy_order(dbp, "AAPL", 10))                         # expected redirect
    print(buy_order(dbp, "MSFT-2025", 1))                     # expected redirect
    print(buy_order(dbp, "AAPL; DROP TABLE buy_orders;", 5))  # expected error
    print(buy_order(dbp, "GOOG", 0))                          # expected error
    print(buy_order(dbp, "A" * 51, 2))                        # expected error