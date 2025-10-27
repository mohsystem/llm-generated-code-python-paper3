import os
import re
from datetime import datetime, timezone

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,32}$')
STOCK_RE = re.compile(r'^[A-Za-z0-9\.-]{1,16}$')
DB_PATH = 'orders_db.csv'
HEADER = 'timestamp,username,stock,quantity'

def _ensure_db_with_header(path: str) -> None:
    # Open file securely with restrictive permissions; write header only if empty
    flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
    mode = 0o600
    fd = os.open(path, flags, mode)
    try:
        st = os.fstat(fd)
        if st.st_size == 0:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
                f.write(HEADER + '\n')
            # Re-open for append after writing header (fd closed by fdopen)
            fd2 = os.open(path, flags, mode)
            os.close(fd2)
        else:
            os.close(fd)
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        raise

def _append_order(username: str, stock: str, qty: int) -> bool:
    try:
        _ensure_db_with_header(DB_PATH)
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        line = f"{ts},{username},{stock},{qty}\n"
        with open(DB_PATH, 'a', encoding='utf-8', newline='') as f:
            f.write(line)
        return True
    except Exception:
        return False

def process_buy_order(username: str, stock_name: str, stock_quantity: int):
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username or ""):
        return None
    if not isinstance(stock_name, str) or not STOCK_RE.fullmatch(stock_name or ""):
        return None
    if not isinstance(stock_quantity, int) or stock_quantity < 1 or stock_quantity > 1_000_000:
        return None

    stock_norm = stock_name.upper()
    if not _append_order(username, stock_norm, stock_quantity):
        return None
    return f"/users/{username}/profile"

def _test(username, stock, qty):
    res = process_buy_order(username, stock, qty)
    print(f"Input: user={username}, stock={stock}, qty={qty}")
    print("Result:", res if res is not None else "ERROR")
    print("----")

if __name__ == "__main__":
    # 5 test cases
    _test("alice_01", "AAPL", 10)
    _test("bob", "GOOG", 100)
    _test("charlie", "msft", 5000)
    _test("bad name", "TSLA", 10)   # invalid username
    _test("dave", "BRK.B", 0)       # invalid quantity