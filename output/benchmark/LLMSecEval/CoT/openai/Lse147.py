# Chain-of-Through process in code generation for Python:
# 1. Problem understanding: Simulate form submission to a buy_order "route" inserting into DB then redirect to stock_view.
# 2. Security requirements: Validate inputs and use parameterized queries to prevent SQL injection; limit quantity.
# 3. Secure coding generation: Use sqlite3 with placeholders, validate stock name and quantity.
# 4. Code review: Ensure connections/cursors closed via context managers, handle exceptions.
# 5. Secure code output: Final functions below with 5 test cases.

import sqlite3
import re
from typing import List, Tuple

def init_db(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS buy_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock_name TEXT NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity > 0),
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)

def _is_valid_stock_name(name: str) -> bool:
    if name is None:
        return False
    name = name.strip()
    if not (1 <= len(name) <= 64):
        return False
    return re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None

def stock_view(db_path: str) -> List[Tuple[int, str, int, str]]:
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute("SELECT id, stock_name, quantity, created_at FROM buy_orders ORDER BY id ASC")
        return cur.fetchall()

def buy_order(db_path: str, stock_name: str, quantity: int):
    if not _is_valid_stock_name(stock_name):
        raise ValueError("Invalid stock name")
    if not isinstance(quantity, int) or quantity <= 0 or quantity > 1_000_000:
        raise ValueError("Invalid quantity")

    with sqlite3.connect(db_path) as conn:
        conn.execute("INSERT INTO buy_orders (stock_name, quantity) VALUES (?, ?)", (stock_name.strip(), quantity))
    return stock_view(db_path)

if __name__ == "__main__":
    db = "py_demo.db"
    init_db(db)

    print("After AAPL:", buy_order(db, "AAPL", 10))
    print("After GOOGL:", buy_order(db, "GOOGL", 5))
    print("After MSFT:", buy_order(db, "MSFT", 15))
    print("After TSLA:", buy_order(db, "TSLA", 1))
    print("After NVDA:", buy_order(db, "NVDA", 20))