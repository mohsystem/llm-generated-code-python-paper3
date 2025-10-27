import re
import sqlite3
from urllib.parse import quote

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
STOCK_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
DB_PATH = "lse146_orders_py.db"

def _ensure_table_exists(conn):
    with conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS buy_orders ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "username TEXT NOT NULL,"
            "stock_name TEXT NOT NULL,"
            "quantity INTEGER NOT NULL CHECK(quantity > 0),"
            "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )

def _validate_inputs(username, stock_name, stock_quantity):
    if username is None or stock_name is None:
        raise ValueError("Inputs cannot be None")
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Invalid username format")
    if not STOCK_RE.fullmatch(stock_name):
        raise ValueError("Invalid stock name format")
    if not isinstance(stock_quantity, int) or stock_quantity < 1 or stock_quantity > 1_000_000:
        raise ValueError("Quantity must be between 1 and 1,000,000")

# Returns redirect URL on success
def place_buy_order(username, stock_name, stock_quantity):
    _validate_inputs(username, stock_name, stock_quantity)
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=5.0)
    try:
        _ensure_table_exists(conn)
        with conn:
            conn.execute(
                "INSERT INTO buy_orders(username, stock_name, quantity) VALUES(?, ?, ?)",
                (username, stock_name, stock_quantity),
            )
        return "/profile/" + quote(username, safe="")
    finally:
        conn.close()

if __name__ == "__main__":
    tests = [
        ("alice", "AAPL", 10),
        ("bob-01", "Microsoft Corp", 250),
        ("charlie", "GOOG", 0),
        ("dave", "Bad'Stock", 5),
        ("eve", "TSLA", 100),
    ]
    for i, (u, s, q) in enumerate(tests, 1):
        try:
            print(f"Test{i}: {place_buy_order(u, s, q)}")
        except Exception as ex:
            print(f"Test{i}: INVALID - {str(ex)}")