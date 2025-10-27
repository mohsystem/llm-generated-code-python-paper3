import sqlite3
from typing import Optional

def init_db(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock TEXT NOT NULL,
                qty INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

def buy_order(db_path: str, stock: str, qty: int) -> int:
    if not stock or not stock.strip():
        raise ValueError("stock is required")
    if qty <= 0:
        raise ValueError("qty must be positive")
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute("INSERT INTO orders(stock, qty) VALUES(?, ?)", (stock, qty))
        return cur.lastrowid

def stock_view(db_path: str) -> str:
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute("SELECT id, stock, qty, created_at FROM orders ORDER BY id")
        rows = cur.fetchall()
        return "\n".join(f"{r[0]},{r[1]},{r[2]},{r[3]}" for r in rows) + ("\n" if rows else "")

if __name__ == "__main__":
    db = "stocks_py.db"
    init_db(db)

    buy_order(db, "AAPL", 10)
    print(stock_view(db), end="")

    buy_order(db, "GOOG", 5)
    print(stock_view(db), end="")

    buy_order(db, "MSFT", 20)
    print(stock_view(db), end="")

    buy_order(db, "TSLA", 3)
    print(stock_view(db), end="")

    buy_order(db, "AMZN", 7)
    print(stock_view(db), end="")