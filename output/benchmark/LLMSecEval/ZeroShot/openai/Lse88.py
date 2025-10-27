from decimal import Decimal, ROUND_HALF_UP, getcontext

# Configure decimal context for currency calculations
getcontext().prec = 28

_PRICE_MAP = {
    "P001": Decimal("9.99"),
    "P002": Decimal("19.99"),
    "P003": Decimal("25.00"),
    "P004": Decimal("123.45"),
    "P005": Decimal("0.50"),
}

_MAX_PAYLOAD_SIZE = 10_000

def _trim_quotes(val: str) -> str:
    if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
        return val[1:-1]
    return val

def calculate_price(yaml_payload: str) -> str:
    if yaml_payload is None:
        return "error: payload is null"
    if len(yaml_payload) > _MAX_PAYLOAD_SIZE:
        return "error: payload too large"

    product_code = None
    quantity_str = None

    for raw_line in yaml_payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = _trim_quotes(value.strip())
        if key == "product_code":
            product_code = value
        elif key == "quantity":
            quantity_str = value

    if not product_code:
        return "error: missing product_code"
    if not (1 <= len(product_code) <= 32) or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in product_code):
        return "error: invalid product_code"

    if not quantity_str:
        return "error: missing quantity"
    if not quantity_str.isdigit():
        return "error: invalid quantity"
    try:
        quantity = int(quantity_str)
    except Exception:
        return "error: invalid quantity"
    if quantity <= 0 or quantity > 1_000_000:
        return "error: quantity out of range"

    price = _PRICE_MAP.get(product_code)
    if price is None:
        return "error: unknown product_code"

    total = (price * Decimal(quantity)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return format(total, "f")

if __name__ == "__main__":
    tests = [
        "product_code: P001\nquantity: 3",
        "# Sample order\nproduct_code: \"P002\"\nquantity: 1",
        "product_code: P999\nquantity: 2",
        "product_code: P001\nquantity: -5",
        "product_code: P004\nquantity: 1000000",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {calculate_price(t)}")