# Chain-of-Through process:
# 1) Problem understanding: Parse "OP A B", execute operation safely, return "Result: <value>" or "Error: <reason>".
# 2) Security requirements: Validate input length, strict tokenization, only whitelisted ops, 64-bit bounds, robust error handling.
# 3) Secure coding generation: Implement safe 64-bit arithmetic checks in Python to emulate fixed-width behavior.
# 4) Code review: Overflow checks, division guards, input validation confirmed.
# 5) Secure code output: Final secure implementation below.

from typing import Tuple

INT64_MIN = -2**63
INT64_MAX = 2**63 - 1

def _in_int64(x: int) -> bool:
    return INT64_MIN <= x <= INT64_MAX

def _parse_int64(s: str) -> Tuple[bool, int]:
    s = s.strip()
    if not s or any(c not in "+-0123456789" for c in s) or s.lstrip("+-").strip() == "":
        return False, 0
    try:
        val = int(s, 10)
    except Exception:
        return False, 0
    if not _in_int64(val):
        return False, 0
    return True, val

def _safe_add(a: int, b: int) -> Tuple[bool, int]:
    res = a + b
    return (_in_int64(res), res)

def _safe_sub(a: int, b: int) -> Tuple[bool, int]:
    res = a - b
    return (_in_int64(res), res)

def _safe_mul(a: int, b: int) -> Tuple[bool, int]:
    # emulate 64-bit overflow check
    res = a * b
    return (_in_int64(res), res)

def _safe_div(a: int, b: int) -> Tuple[bool, int]:
    if b == 0:
        return False, 0
    if a == INT64_MIN and b == -1:
        return False, 0
    # Python truncates toward negative infinity with // for negatives; use int(a/b) to truncate toward zero
    res = int(a / b)
    return (_in_int64(res), res)

def process_input(input_str: str) -> str:
    if input_str is None:
        return "Error: input is null"
    s = input_str.strip()
    if not s:
        return "Error: input is empty"
    if len(s) > 1000:
        return "Error: input too long"

    parts = s.split()
    if len(parts) != 3:
        return "Error: expected format 'OP A B' with exactly three tokens"

    op = parts[0].upper()
    ok_a, a = _parse_int64(parts[1])
    if not ok_a:
        return "Error: invalid number for A"
    ok_b, b = _parse_int64(parts[2])
    if not ok_b:
        return "Error: invalid number for B"

    if op == "ADD":
        ok, res = _safe_add(a, b)
        return f"Result: {res}" if ok else "Error: overflow in addition"
    elif op == "SUB":
        ok, res = _safe_sub(a, b)
        return f"Result: {res}" if ok else "Error: overflow in subtraction"
    elif op == "MUL":
        ok, res = _safe_mul(a, b)
        return f"Result: {res}" if ok else "Error: overflow in multiplication"
    elif op == "DIV":
        ok, res = _safe_div(a, b)
        return f"Result: {res}" if ok else "Error: division error (division by zero or overflow)"
    else:
        return "Error: unsupported operation"

def main():
    tests = [
        "ADD 5 7",
        "DIV 10 0",
        "MUL 9223372036854775807 2",
        "SUB -5 -10",
        "FOO 1 2",
    ]
    for t in tests:
        print(f'Input: "{t}" -> {process_input(t)}')

if __name__ == "__main__":
    main()