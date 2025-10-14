# Steps applied:
# 1) Problem understanding
# 2) Security requirements
# 3) Secure coding generation
# 4) Code review
# 5) Secure code output

import re
import json
from dataclasses import dataclass
from typing import Dict, Optional

@dataclass(frozen=True)
class Product:
    id: int
    name: str
    price: float
    stock: int

class _ProductRepository:
    NAME_ALLOWED = re.compile(r'^[A-Za-z0-9 _\-]+$')

    def __init__(self, products):
        self._by_id: Dict[int, Product] = {}
        self._by_name: Dict[str, Product] = {}
        for p in products:
            self._by_id[p.id] = p
            self._by_name[self._normalize_name(p.name)] = p

    @classmethod
    def _normalize_name(cls, name: str) -> Optional[str]:
        if name is None:
            return None
        trimmed = name.strip()
        collapsed = re.sub(r'\s+', ' ', trimmed)
        if not cls.NAME_ALLOWED.match(collapsed):
            return None
        return collapsed.lower()

    def find_by_id_secure(self, pid: int) -> Optional[Product]:
        if not isinstance(pid, int) or pid < 0 or pid > 1_000_000_000:
            return None
        return self._by_id.get(pid)

    def find_by_name_secure(self, name: str) -> Optional[Product]:
        norm = self._normalize_name(name)
        if norm is None:
            return None
        return self._by_name.get(norm)

class Task137:
    ID_PATTERN = re.compile(r'^\s*id\s*:\s*(\d{1,9})\s*$', re.IGNORECASE)
    NAME_PATTERN = re.compile(r'^\s*name\s*:\s*(.+)\s*$', re.IGNORECASE)

    def __init__(self, repo: _ProductRepository):
        self.repo = repo

    def process_user_input(self, input_str: str) -> str:
        if input_str is None:
            return self._error("Invalid input")
        if len(input_str) > 1024:
            return self._error("Input too long")

        m = self.ID_PATTERN.match(input_str)
        if m:
            try:
                pid = int(m.group(1))
            except Exception:
                return self._error("Invalid ID")
            p = self.repo.find_by_id_secure(pid)
            if not p:
                return self._not_found()
            return self._to_json(p)

        m = self.NAME_PATTERN.match(input_str)
        if m:
            name = m.group(1)
            p = self.repo.find_by_name_secure(name)
            if not p:
                return self._not_found()
            return self._to_json(p)

        return self._error("Unsupported query. Use 'id:<digits>' or 'name:<text>'")

    def _to_json(self, p: Product) -> str:
        # Ensure safe serialization
        obj = {
            "id": p.id,
            "name": p.name,
            "price": float(f"{p.price:.2f}"),
            "stock": p.stock
        }
        return json.dumps(obj, separators=(',', ':'))

    def _error(self, msg: str) -> str:
        return json.dumps({"error": msg}, separators=(',', ':'))

    def _not_found(self) -> str:
        return json.dumps({"message": "Product not found"}, separators=(',', ':'))

def _build_repository():
    return _ProductRepository([
        Product(1001, "Wireless Mouse", 25.99, 42),
        Product(1002, "Mechanical Keyboard", 79.49, 12),
        Product(1003, "USB-C Cable", 9.99, 150),
        Product(1004, "27-inch Monitor", 199.99, 8),
        Product(1005, "Webcam Pro", 49.95, 5),
    ])

def main():
    repo = _build_repository()
    service = Task137(repo)
    tests = [
        "id:1001",
        "name:Wireless Mouse",
        "name:   usb-c   cable ",
        "id:9999",
        "name:DROP TABLE products;--"
    ]
    for t in tests:
        print("Query:", t)
        print("Result:", service.process_user_input(t))

if __name__ == "__main__":
    main()