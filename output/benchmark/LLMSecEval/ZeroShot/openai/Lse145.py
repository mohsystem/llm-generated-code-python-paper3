import re
import time
from typing import List, Dict, Any

# Simple in-memory "database"
DB: List[Dict[str, Any]] = []

_STOCK_RE = re.compile(r"^[A-Z0-9.-]{1,15}$")


def buy_function(stock_name: str) -> str:
    """
    Normalize and validate stock name.
    """
    if stock_name is None:
        raise ValueError("stock_name must not be None")
    trimmed = stock_name.strip()
    if not trimmed:
        raise ValueError("Stock name must not be empty")
    normalized = trimmed.upper()
    if not _STOCK_RE.fullmatch(normalized):
        raise ValueError("Invalid stock name format")
    return normalized


def buy_stock(stock_name: str, quantity: int) -> Dict[str, Any]:
    """
    Validate and insert into "database".
    Returns the created record.
    """
    normalized = buy_function(stock_name)
    if not isinstance(quantity, int):
        raise ValueError("Quantity must be an integer")
    if quantity <= 0 or quantity > 1_000_000:
        raise ValueError("Quantity out of allowed range")
    record = {
        "stock": normalized,
        "quantity": quantity,
        "ts": int(time.time()),
    }
    # Simulate parameterized insert
    DB.append(record)
    return record


def _print_db() -> None:
    print(f"DB size: {len(DB)}")
    for r in DB:
        print(r)


if __name__ == "__main__":
    # 5 test cases
    try:
        print("Test 1:", buy_stock("AAPL", 10))
    except Exception as e:
        print("Test 1 failed:", e)

    try:
        print("Test 2:", buy_stock("  msft ", 25))
    except Exception as e:
        print("Test 2 failed:", e)

    try:
        print("Test 3:", buy_stock("AAPL; DROP TABLES", 5))
    except Exception as e:
        print("Test 3 expected failure:", e)

    try:
        print("Test 4:", buy_stock("GOOG", -5))
    except Exception as e:
        print("Test 4 expected failure:", e)

    try:
        print("Test 5:", buy_stock("BRK.B", 100))
    except Exception as e:
        print("Test 5 failed:", e)

    _print_db()