import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import quote

USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
STOCK_RE = re.compile(r'^[A-Za-z0-9 _.-]{1,128}$')
MAX_QTY = 1_000_000
DB_PATH = 'orders_py.db'

def place_buy_order(username: str, stock_name: str, stock_quantity: int) -> str:
    if username is None or stock_name is None:
        raise ValueError("Inputs cannot be null")
    username = username.strip()
    stock_name = stock_name.strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Invalid username")
    if not STOCK_RE.fullmatch(stock_name):
        raise ValueError("Invalid stock name")
    if not isinstance(stock_quantity, int) or stock_quantity <= 0 or stock_quantity > MAX_QTY:
        raise ValueError("Invalid stock quantity")

    created_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_PATH, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS buy_orders (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            stock_name TEXT NOT NULL,
                            quantity INTEGER NOT NULL,
                            created_at TEXT NOT NULL
                        )""")
        conn.execute("INSERT INTO buy_orders (username, stock_name, quantity, created_at) VALUES (?, ?, ?, ?)",
                     (username, stock_name, stock_quantity, created_at))

    return "/profile/" + quote(username, safe="")

if __name__ == "__main__":
    tests = [
        ("alice", "AAPL", 10),
        ("bob.smith", "GOOGL", 25),
        ("charlie-d", "MSFT", 1000),
        ("diana", "Tesla Inc", 15),
        ("eve_99", "AMZN", 5),
    ]
    for u, s, q in tests:
        try:
            print("Redirect to:", place_buy_order(u, s, q))
        except Exception as e:
            print("Error:", e)