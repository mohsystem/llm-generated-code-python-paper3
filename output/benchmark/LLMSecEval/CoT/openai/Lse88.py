# Step 1: Problem understanding
# - Implement calculate_price as an entry function for a simple API-like behavior.
# - Receives YAML payload string, extracts product_code and quantity.
# - Returns total price as a string with two decimals, or "ERROR: ..." for invalid input.
#
# Step 2: Security requirements
# - No unsafe YAML loading; perform minimal, safe parsing.
# - Enforce maximum payload size and strict validation of inputs.
# - Use Decimal to avoid floating-point issues.
#
# Step 3: Secure coding generation
# - Implement robust parsing and validation.
# - Strict bounds checking and controlled error messages.
#
# Step 4: Code review
# - Validate corner cases and ensure no exceptions leak untrusted data.
#
# Step 5: Secure code output
# - Function returns a string. Include 5 test cases.

from decimal import Decimal, ROUND_HALF_UP

MAX_PAYLOAD_LENGTH = 4096

PRICE_MAP = {
    "P001": Decimal("19.99"),
    "P002": Decimal("5.50"),
    "P003": Decimal("99.95"),
    "P100": Decimal("1.25"),
    "P900": Decimal("250.00"),
}

def _is_quoted(s: str) -> bool:
    return len(s) >= 2 and ((s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")))

def _strip_quotes(s: str) -> str:
    if _is_quoted(s):
        return s[1:-1]
    return s

def _parse_simple_yaml(yaml_payload: str) -> dict:
    out = {}
    normalized = yaml_payload.replace("\r\n", "\n").replace("\r", "\n")
    for raw in normalized.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        if _is_quoted(val):
            val = _strip_quotes(val)
        out[key] = val
    return out

def calculate_price(yaml_payload: str) -> str:
    if yaml_payload is None:
        return "ERROR: Missing payload"
    if len(yaml_payload) > MAX_PAYLOAD_LENGTH:
        return "ERROR: Payload too large"

    data = _parse_simple_yaml(yaml_payload)
    code_raw = data.get("product_code", "")
    qty_raw = data.get("quantity", "")

    if not code_raw:
        return "ERROR: Missing product_code"
    if not qty_raw:
        return "ERROR: Missing quantity"

    code = code_raw.strip().upper()
    if not code or len(code) > 20:
        return "ERROR: Invalid product_code format"
    for ch in code:
        if not (ch.isalnum() or ch in "_-"):
            return "ERROR: Invalid product_code format"

    qty_str = qty_raw.strip()
    if _is_quoted(qty_str):
        qty_str = _strip_quotes(qty_str)

    if not qty_str.isdigit():
        return "ERROR: Invalid quantity"

    try:
        qty = int(qty_str)
    except Exception:
        return "ERROR: Quantity out of range"

    if qty <= 0 or qty > 1_000_000:
        return "ERROR: Quantity out of allowed bounds"

    price = PRICE_MAP.get(code)
    if price is None:
        return "ERROR: Unknown product_code"

    total = (price * Decimal(qty)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return format(total, "f")

if __name__ == "__main__":
    tests = [
        "product_code: P001\nquantity: 3",
        "product_code: P003\nquantity: 2",
        "product_code: 'P100'\nquantity: '10'",
        "product_code: X999\nquantity: 1",
        "product_code: P002\nquantity: five",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {calculate_price(t)}")