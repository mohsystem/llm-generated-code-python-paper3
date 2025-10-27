import sqlite3
import re
import sys
from datetime import datetime

# Step 1: Purpose - secure functions to process buy stock request with validation and DB insert.
# Steps 2-5: Applied via input validation, parameterized statements, and safe error handling.

_conn = sqlite3.connect(":memory:")
_conn.execute("""
    CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stock_name TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
""")
_conn.commit()

def buy_function(stock_name: str) -> str:
    if stock_name is None:
        raise ValueError("Stock name is required.")
    name = stock_name.strip()
    if not name:
        raise ValueError("Stock name cannot be empty.")
    if not re.fullmatch(r"[A-Za-z]{1,10}", name):
        raise ValueError("Stock name must be 1-10 alphabetic characters.")
    return name.upper()

def buy_stock(stock_name: str, quantity: int) -> int:
    if not isinstance(quantity, int):
        raise ValueError("Quantity must be an integer.")
    if quantity <= 0 or quantity > 1_000_000:
        raise ValueError("Quantity must be between 1 and 1,000,000.")
    symbol = buy_function(stock_name)
    cur = _conn.cursor()
    cur.execute("INSERT INTO purchases (stock_name, quantity) VALUES (?, ?)", (symbol, quantity))
    _conn.commit()
    return cur.lastrowid

def _run_test(label, stock, qty):
    try:
        rowid = buy_stock(stock, qty)
        print(f"{label} OK -> rowId={rowid}")
    except Exception as e:
        print(f"{label} ERR -> {e}")

if __name__ == "__main__":
    # 5 test cases
    _run_test("T1", "AAPL", 10)     # valid
    _run_test("T2", "goog", 5)      # valid (normalized)
    _run_test("T3", "BAD!", 3)      # invalid name
    _run_test("T4", "DROP", 0)      # invalid quantity
    _run_test("T5", "msft", 100)    # valid