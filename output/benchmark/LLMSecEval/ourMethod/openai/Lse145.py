import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Simple in-memory database
@dataclass
class Purchase:
    id: int
    stock_name: str
    quantity: int

class Database:
    def __init__(self) -> None:
        self._purchases: List[Purchase] = []
        self._next_id: int = 1
        self._max_records: int = 1_000_000

    def insert(self, stock_name: str, quantity: int) -> int:
        if len(self._purchases) >= self._max_records:
            raise RuntimeError("Capacity reached")
        pid = self._next_id
        self._purchases.append(Purchase(pid, stock_name, quantity))
        self._next_id += 1
        return pid

    def all(self) -> List[Purchase]:
        return list(self._purchases)

# Allowed tickers
ALLOWED_TICKERS = {"AAPL", "GOOG", "MSFT", "TSLA", "AMZN"}

# Validation: 1-15 chars, uppercase A-Z first, then A-Z, 0-9, '.', '-'
TICKER_RE = re.compile(r"^[A-Z][A-Z0-9.\-]{0,14}$")

def sanitize_and_validate_stock_name(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None
    trimmed = name.strip()
    if not trimmed:
        return None
    upper = trimmed.upper()
    if len(upper) > 15:
        return None
    if not TICKER_RE.fullmatch(upper):
        return None
    return upper

def is_valid_quantity(q: int) -> bool:
    return isinstance(q, int) and 1 <= q <= 1_000_000

# buy_function: verify stock availability
def buy_function(stock_name: str) -> bool:
    return stock_name in ALLOWED_TICKERS

# buy_stock: validate, call buy_function, insert
def buy_stock(db: Database, stock_name_input: str, quantity: int) -> str:
    if db is None:
        return "ERROR: Internal database unavailable"
    if not is_valid_quantity(quantity):
        return "ERROR: Invalid quantity"
    sanitized = sanitize_and_validate_stock_name(stock_name_input)
    if sanitized is None:
        return "ERROR: Invalid stock name"
    if not buy_function(sanitized):
        return "ERROR: Stock not available"
    try:
        pid = db.insert(sanitized, quantity)
        return f"SUCCESS: id={pid} stock={sanitized} qty={quantity}"
    except RuntimeError:
        return "ERROR: Database capacity reached"
    except Exception:
        return "ERROR: Internal error"

def main() -> None:
    db = Database()
    tests: List[Tuple[str, int]] = [
        ("AAPL", 10),
        (" msft ", 5),
        ("AAPL;DELETE", 1),
        ("GOOG", 0),
        ("IBM", 1),
    ]
    for i, (s, q) in enumerate(tests, 1):
        print(f"Test {i}: {buy_stock(db, s, q)}")
    for p in db.all():
        print(f"Record: id={p.id} stock={p.stock_name} qty={p.quantity}")

if __name__ == "__main__":
    main()