from typing import Dict, Optional

PRICE_MAP: Dict[str, float] = {
    "A1": 9.99,
    "B2": 5.00,
    "C3": 2.50,
    "D4": 100.00,
    "E5": 0.75,
}

def get_price_for_product_code(code: str) -> float:
    if code is None:
        return -1.0
    return PRICE_MAP.get(code, -1.0)

def _is_ascii_printable(payload: str) -> bool:
    for ch in payload:
        o = ord(ch)
        if ch in ("\n", "\r", "\t"):
            continue
        if not (32 <= o <= 126):
            return False
    return True

def _strip_quotes(s: str) -> str:
    t = s.strip()
    if len(t) >= 2 and ((t[0] == t[-1] == "'") or (t[0] == t[-1] == '"')):
        return t[1:-1]
    return t

def _parse_simple_yaml_to_map(yaml_payload: str) -> Optional[Dict[str, str]]:
    lines = yaml_payload.splitlines()
    if len(lines) > 200:
        return None
    out: Dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = _strip_quotes(val.strip())
        if key in ("product_code", "quantity"):
            out[key] = val
    return out

def _is_valid_product_code(code: str) -> bool:
    if not code or len(code) > 20:
        return False
    for ch in code:
        if ch.isalnum() or ch in ("_", "-"):
            continue
        return False
    return True

def _parse_positive_int(s: str, min_v: int, max_v: int) -> Optional[int]:
    t = s.strip()
    if not t or not t.isdigit():
        return None
    try:
        v = int(t, 10)
    except ValueError:
        return None
    if v < min_v or v > max_v:
        return None
    return v

def calculate_price(yaml_payload: str) -> str:
    if yaml_payload is None or not isinstance(yaml_payload, str):
        return "error: invalid_request"
    if len(yaml_payload) > 4096:
        return "error: invalid_request"
    if not _is_ascii_printable(yaml_payload):
        return "error: invalid_request"

    data = _parse_simple_yaml_to_map(yaml_payload)
    if data is None:
        return "error: invalid_request"

    product_code = data.get("product_code")
    quantity_str = data.get("quantity")
    if product_code is None or quantity_str is None:
        return "error: invalid_request"
    if not _is_valid_product_code(product_code):
        return "error: invalid_request"
    qty = _parse_positive_int(quantity_str, 1, 1_000_000)
    if qty is None:
        return "error: invalid_request"

    price = get_price_for_product_code(product_code)
    if price < 0.0:
        return "error: unknown_product_code"

    total = price * qty
    return f"total_price: {total:.2f}"

if __name__ == "__main__":
    tests = [
        "product_code: A1\nquantity: 3\n",
        "product_code: B2\nquantity: 10\n",
        "product_code: Z9\nquantity: 1\n",
        "product_code: C3\nquantity: -2\n",
        " product_code : 'E5' \n quantity : 4 \n",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} -> {calculate_price(t)}")