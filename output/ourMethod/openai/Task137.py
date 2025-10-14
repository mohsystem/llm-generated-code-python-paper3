from dataclasses import dataclass
from typing import List, Optional

@dataclass(frozen=True)
class Product:
    id: int
    name: str
    price: float
    stock: int

class ProductDB:
    def __init__(self, products: List[Product]) -> None:
        self._by_id = {p.id: p for p in products}
        self._by_name = {p.name: p for p in products}

    def find_by_id(self, pid: int) -> Optional[Product]:
        return self._by_id.get(pid)

    def find_by_name(self, name: str) -> Optional[Product]:
        return self._by_name.get(name)

def _escape_json(s: str) -> str:
    out = []
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)

def _error_json(msg: str) -> str:
    return f'{{"ok":false,"error":"{_escape_json(msg)}"}}'

def _ok_json(p: Product) -> str:
    return (
        '{"ok":true,"product":{'
        f'"id":{p.id},'
        f'"name":"{_escape_json(p.name)}",'
        f'"price":{p.price:.2f},'
        f'"stock":{p.stock}'
        "}}"
    )

def _is_valid_digits(s: str) -> bool:
    return 1 <= len(s) <= 9 and s.isdigit()

def _is_valid_name(s: str) -> bool:
    if not (1 <= len(s) <= 50):
        return False
    for ch in s:
        if not (ch.isalnum() or ch in {' ', '-', '_'}):
            return False
    return True

def process_query(query: str) -> str:
    if query is None:
        return _error_json("Query must not be null")
    if len(query) == 0 or len(query) > 100:
        return _error_json("Query length must be between 1 and 100")

    db = ProductDB([
        Product(1001, "Widget", 9.99, 100),
        Product(1002, "Gadget", 12.49, 50),
        Product(1003, "Thingamajig", 7.95, 0),
        Product(2001, "Doodad", 5.00, 25),
        Product(3001, "Sprocket", 15.75, 10),
    ])

    if query.startswith("id="):
        id_str = query[3:]
        if not _is_valid_digits(id_str):
            return _error_json("Invalid id format. Expected 1-9 digits.")
        try:
            pid = int(id_str)
        except ValueError:
            return _error_json("Invalid id value")
        if pid <= 0 or pid > 1_000_000_000:
            return _error_json("Id out of allowed range")
        p = db.find_by_id(pid)
        if p is None:
            return _error_json("Product not found")
        return _ok_json(p)
    elif query.startswith("name="):
        name = query[5:]
        if not _is_valid_name(name):
            return _error_json("Invalid name. Allowed: A-Z a-z 0-9 space - _ (1-50 chars)")
        p = db.find_by_name(name)
        if p is None:
            return _error_json("Product not found")
        return _ok_json(p)
    else:
        return _error_json("Invalid query. Use id=<digits> or name=<allowed_name>")

if __name__ == "__main__":
    tests = [
        "id=1002",
        "name=Widget",
        "id=9999",
        "name=Invalid*Name!",
        "foo=bar",
    ]
    for q in tests:
        print(f"Query: {q}")
        print(f"Result: {process_query(q)}")
        print("---")