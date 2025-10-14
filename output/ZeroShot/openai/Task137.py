from dataclasses import dataclass
from typing import Dict, List, Optional
import re

@dataclass(frozen=True)
class Product:
    id: int
    name: str
    price: float
    description: str

SAFE_CHARS = re.compile(r"^[A-Za-z0-9 _'\-\.]{1,100}$")

def _normalize_query(q: str) -> str:
    if q is None:
        raise ValueError("Query cannot be null.")
    q = q.strip()
    if not q:
        raise ValueError("Query cannot be empty.")
    if len(q) > 100:
        raise ValueError("Query too long.")
    if not SAFE_CHARS.fullmatch(q):
        raise ValueError("Query contains disallowed characters.")
    return q.lower()

def _normalize_id(pid: int) -> int:
    if pid is None:
        raise ValueError("ID cannot be null.")
    if not isinstance(pid, int):
        raise ValueError("ID must be an integer.")
    if pid < 0 or pid > 1_000_000_000:
        raise ValueError("ID out of allowed range.")
    return pid

# Function: query product details by ID
def get_product_by_id(product_table: Dict[int, Product], pid: int) -> Optional[Product]:
    if product_table is None:
        raise ValueError("product_table cannot be None")
    safe_id = _normalize_id(pid)
    return product_table.get(safe_id)

# Function: query product details by name (case-insensitive substring)
def get_products_by_name(product_table: Dict[int, Product], name_query: str) -> List[Product]:
    if product_table is None:
        raise ValueError("product_table cannot be None")
    q = _normalize_query(name_query)
    results = []
    for p in product_table.values():
        if q in p.name.lower():
            results.append(p)
    return results

def build_sample_table() -> Dict[int, Product]:
    return {
        1: Product(1, "Apple iPhone 14", 799.00, "Latest Apple smartphone"),
        2: Product(2, "Samsung Galaxy S23", 749.99, "Flagship Android phone"),
        3: Product(3, "Google Pixel 8", 699.00, "Google's premium device"),
        4: Product(4, "Apple AirPods Pro", 249.00, "Noise-cancelling earbuds"),
        5: Product(5, "Dell XPS 13", 1199.00, "Ultrabook laptop"),
    }

def main():
    table = build_sample_table()

    # Test case 1: by ID existing
    print("Test1 (ID=3):", get_product_by_id(table, 3))

    # Test case 2: by ID not existing
    print("Test2 (ID=999):", get_product_by_id(table, 999))

    # Test case 3: by name "apple"
    print("Test3 (name='apple'):")
    for p in get_products_by_name(table, "apple"):
        print(" ", p)

    # Test case 4: by name "XPS"
    print("Test4 (name='XPS'):")
    for p in get_products_by_name(table, "XPS"):
        print(" ", p)

    # Test case 5: invalid query input
    try:
        print("Test5 (invalid name):")
        print(get_products_by_name(table, "bad; DROP TABLE product;--"))
    except ValueError as e:
        print("  Caught expected error:", e)

if __name__ == "__main__":
    main()