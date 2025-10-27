from dataclasses import dataclass
from datetime import datetime
from typing import List

MAX_STOCK_NAME_LEN = 64
MAX_QUANTITY = 1_000_000

@dataclass
class Order:
    stock_name: str
    quantity: int
    created_at: datetime

class InMemoryDatabase:
    def __init__(self) -> None:
        self._orders: List[Order] = []

    def insert_order(self, stock_name: str, quantity: int) -> bool:
        self._orders.append(Order(stock_name=stock_name, quantity=quantity, created_at=datetime.now()))
        return True

    def get_all(self) -> List[Order]:
        return list(self._orders)

def sanitize_stock_name(name: str) -> str:
    if name is None:
        return ""
    s = name.strip()
    if len(s) > MAX_STOCK_NAME_LEN:
        s = s[:MAX_STOCK_NAME_LEN]
    return s

def is_valid_stock_name(name: str) -> bool:
    if not name or len(name) < 1 or len(name) > MAX_STOCK_NAME_LEN:
        return False
    for ch in name:
        if not (ch.isalnum() or ch in [' ', '_', '-', '.']):
            return False
    return True

def is_valid_quantity(qty: int) -> bool:
    return isinstance(qty, int) and 1 <= qty <= MAX_QUANTITY

def stock_view(db: InMemoryDatabase) -> str:
    lines = ["Stock Orders:"]
    for idx, o in enumerate(db.get_all(), start=1):
        lines.append(f"{idx}. {o.stock_name} - {o.quantity} @ {o.created_at.isoformat(sep=' ', timespec='seconds')}")
    return "\n".join(lines) + "\n"

def render_form() -> str:
    return """<!doctype html>
<html><head><meta charset="utf-8"><title>Buy Order</title></head>
<body>
<h1>Buy Order</h1>
<form method="POST" action="/buy_order">
  <label>Stock Name: <input type="text" name="stock" maxlength="64" required></label><br>
  <label>Quantity: <input type="number" name="qty" min="1" max="1000000" required></label><br>
  <button type="submit">Submit</button>
</form>
</body></html>
"""

def buy_order(db: InMemoryDatabase, stock_name_input: str, quantity_input: int) -> str:
    stock_name = sanitize_stock_name(stock_name_input)
    if not is_valid_stock_name(stock_name):
        return "Error: invalid stock name."
    if not is_valid_quantity(quantity_input):
        return "Error: invalid quantity."
    if not db.insert_order(stock_name, quantity_input):
        return "Error: failed to insert order."
    return "OK: Order inserted. Redirecting to /stock_view ...\n" + stock_view(db)

def main():
    db = InMemoryDatabase()
    print("== Rendered Form (Demo) ==")
    print(render_form())

    # 5 test cases
    print("Test 1:", buy_order(db, "AAPL", 10))
    print("Test 2:", buy_order(db, "GOOG", 25))
    print("Test 3:", buy_order(db, "MSFT", 0))
    print("Test 4:", buy_order(db, "DROP TABLE;--", 5))
    print("Test 5:", buy_order(db, "BRK.B Class A", 100))

if __name__ == "__main__":
    main()