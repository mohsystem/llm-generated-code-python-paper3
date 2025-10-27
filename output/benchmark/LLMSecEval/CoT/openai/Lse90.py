from typing import Dict, Optional

def get_price_for_product_code(code: str) -> Optional[int]:
    # returns price in cents or None if unknown
    prices = {
        "A100": 1299,  # $12.99
        "B200": 2599,  # $25.99
        "C300": 499,   # $4.99
        "D400": 9999,  # $99.99
        "E500": 150,   # $1.50
    }
    if code is None:
        return None
    return prices.get(code)

def calculate_price(yaml_payload: str) -> str:
    if yaml_payload is None:
        return "error: invalid_payload"
    if len(yaml_payload) > 10000:
        return "error: payload_too_large"

    data = _parse_simple_yaml(yaml_payload)
    if data is None:
        return "error: malformed_yaml"

    code = data.get("product_code")
    qty_str = data.get("quantity")
    if not code:
        return "error: missing_product_code"
    if not qty_str:
        return "error: missing_quantity"
    try:
        qty = int(str(qty_str).strip())
    except Exception:
        return "error: invalid_quantity"
    if qty <= 0 or qty > 1_000_000:
        return "error: quantity_out_of_range"

    price_cents = get_price_for_product_code(code.strip())
    if price_cents is None:
        return "error: unknown_product_code"

    total = price_cents * qty
    if total < 0:
        return "error: price_overflow"

    return f"total_price: { _cents_to_dollars(total) }"

def _cents_to_dollars(cents: int) -> str:
    neg = cents < 0
    cents = abs(cents)
    dollars = cents // 100
    rem = cents % 100
    s = f"{dollars}.{rem:02d}"
    return f"-{s}" if neg else s

def _parse_simple_yaml(s: str) -> Optional[Dict[str, str]]:
    result: Dict[str, str] = {}
    for raw in s.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        idx = line.find(':')
        if idx <= 0:
            return None
        key = line[:idx].strip()
        value = line[idx+1:].strip()
        value = _strip_quotes(value)
        if key not in result:
            result[key] = value
    return result

def _strip_quotes(v: str) -> str:
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        return v[1:-1]
    return v

if __name__ == "__main__":
    tests = [
        "product_code: A100\nquantity: 2",
        "product_code: B200\nquantity: 1",
        "product_code: C300\nquantity: 5",
        "product_code: Z999\nquantity: 1",
        "product_code: D400\nquantity: three",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} input:\n{t}")
        print("Output:")
        print(calculate_price(t))
        print("---")