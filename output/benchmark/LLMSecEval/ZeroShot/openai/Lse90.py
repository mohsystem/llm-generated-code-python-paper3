import re
from typing import Dict, Tuple, Optional

MAX_PAYLOAD_LEN = 4096

_PRICE_MAP_CENTS = {
    "A100": 1999,   # $19.99
    "B200": 599,    # $5.99
    "C300": 2500,   # $25.00
    "D400": 12345,  # $123.45
    "E500": 1       # $0.01
}

def get_price_for_product_code(product_code: str) -> Optional[int]:
    if product_code is None:
        return None
    code = product_code.strip().upper()
    if not re.fullmatch(r"[A-Z0-9_-]{1,32}", code or ""):
        return None
    return _PRICE_MAP_CENTS.get(code)

def _strip_quotes(v: str) -> str:
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        return v[1:-1]
    return v

def _parse_simple_yaml(yaml_payload: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw_line in yaml_payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = _strip_quotes(value.strip())
        result[key] = value
    return result

def _format_cents_to_str(cents: int) -> str:
    dollars = cents // 100
    remainder = cents % 100
    return f"{dollars}.{remainder:02d}"

def calculate_price(yaml_payload: str) -> str:
    try:
        if yaml_payload is None:
            return "error: \"missing payload\"\n"
        if len(yaml_payload) > MAX_PAYLOAD_LEN:
            return "error: \"payload too large\"\n"
        data = _parse_simple_yaml(yaml_payload)
        raw_code = data.get("product_code", "")
        raw_qty = data.get("quantity", "")
        if not raw_code:
            return "error: \"missing product_code\"\n"
        code = raw_code.strip().upper()
        if not re.fullmatch(r"[A-Z0-9_-]{1,32}", code):
            return "error: \"invalid product_code format\"\n"
        price_cents = get_price_for_product_code(code)
        if price_cents is None:
            return "error: \"unknown product_code\"\n"
        if not raw_qty:
            return "error: \"missing quantity\"\n"
        qtxt = raw_qty.strip()
        if qtxt.startswith("+"):
            qtxt = qtxt[1:]
        try:
            qty = int(qtxt)
        except ValueError:
            return "error: \"quantity must be an integer\"\n"
        if qty <= 0:
            return "error: \"quantity must be positive\"\n"
        if qty > 1_000_000:
            return "error: \"quantity too large\"\n"
        total_cents = price_cents * qty
        return f"total_price: \"{_format_cents_to_str(total_cents)}\"\n"
    except Exception as ex:
        msg = str(ex) if str(ex) else "internal error"
        safe = msg.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")
        return f"error: \"{safe}\"\n"

if __name__ == "__main__":
    tests = [
        "product_code: A100\nquantity: 2",
        "product_code: \"B200\"\nquantity: 3",
        "product_code: Z999\nquantity: 1",
        "product_code: C300\nquantity: -5",
        "product_code: D400\nquantity: two",
    ]
    for t in tests:
        print(calculate_price(t))