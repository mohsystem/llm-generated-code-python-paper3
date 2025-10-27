import re
from typing import Dict

MAX_INPUT_LEN = 4096
MAX_KEY_VAL_LEN = 64

PRICE_CENTS: Dict[str, int] = {
    "P001": 999,   # 9.99
    "P002": 550,   # 5.50
    "P003": 2000,  # 20.00
}

PRODUCT_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
INTEGER_RE = re.compile(r"^[+-]?\d{1,9}$")


def _strip_quotes(s: str) -> str:
    if len(s) >= 2 and ((s[0] == s[-1]) and s[0] in ("'", '"')):
        return s[1:-1]
    return s


def calculate_price(yaml_payload: str) -> str:
    try:
        if yaml_payload is None:
            return "error: invalid input"
        if not isinstance(yaml_payload, str):
            return "error: invalid input"
        data_bytes = yaml_payload.encode("utf-8", errors="strict")
        if len(data_bytes) == 0 or len(data_bytes) > MAX_INPUT_LEN:
            return "error: invalid input"
        if "\x00" in yaml_payload:
            return "error: invalid input"

        product_code = None
        quantity_str = None

        for raw_line in yaml_payload.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if len(k) == 0 or len(k) > MAX_KEY_VAL_LEN or len(v) > MAX_KEY_VAL_LEN:
                return "error: invalid input"
            v = _strip_quotes(v)
            if k == "product_code":
                product_code = v
            elif k == "quantity":
                quantity_str = v

        if product_code is None or quantity_str is None:
            return "error: missing product_code or quantity"

        if not PRODUCT_CODE_RE.match(product_code):
            return "error: invalid product_code"

        if not INTEGER_RE.match(quantity_str):
            return "error: invalid quantity"
        try:
            quantity = int(quantity_str, 10)
        except Exception:
            return "error: invalid quantity"
        if quantity <= 0 or quantity > 1_000_000:
            return "error: invalid quantity"

        price_cents = PRICE_CENTS.get(product_code)
        if price_cents is None:
            return "error: unknown product_code"

        total_cents = price_cents * quantity
        if total_cents < 0:  # overflow guard (Python int won't overflow, but be consistent)
            return "error: overflow"

        dollars = total_cents // 100
        cents = abs(total_cents % 100)
        return f"{dollars}.{cents:02d}"
    except Exception:
        return "error: processing failed"


if __name__ == "__main__":
    tests = [
        "product_code: P001\nquantity: 3\n",
        "quantity: 10\nproduct_code: P002\n",
        "product_code: UNKNOWN\nquantity: 1\n",
        "product_code: P001\nquantity: -5\n",
        "product_code: P003\n",
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {calculate_price(t)}")