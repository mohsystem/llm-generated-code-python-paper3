import sys

MIN_INT64 = -2**63
MAX_INT64 = 2**63 - 1

def process_input(input_str: str) -> str:
    if input_str is None:
        return "ERROR: Empty input"
    s = input_str.strip()
    if not s:
        return "ERROR: Empty input"
    parts = s.split()
    if len(parts) != 3:
        return "ERROR: Expected format: OP A B"
    op = parts[0].upper()
    try:
        a = parse_int64(parts[1])
        b = parse_int64(parts[2])
    except ValueError:
        return "ERROR: Invalid number"

    try:
        if op == "ADD":
            return checked_result(a + b)
        elif op == "SUB":
            return checked_result(a - b)
        elif op == "MUL":
            return checked_result(a * b)
        elif op == "DIV":
            if b == 0:
                return "ERROR: Division by zero"
            if a == MIN_INT64 and b == -1:
                return "ERROR: Overflow"
            res = trunc_div(a, b)
            return checked_result(res)
        elif op == "MOD":
            if b == 0:
                return "ERROR: Modulus by zero"
            res = a % b
            return checked_result(res)
        elif op == "POW":
            if b < 0:
                return "ERROR: Negative exponent"
            if a == 0 and b == 0:
                return "ERROR: Undefined 0^0"
            try:
                res = pow_checked(a, b)
                return checked_result(res)
            except OverflowError:
                return "ERROR: Overflow"
        else:
            return "ERROR: Unknown operation"
    except Exception:
        return "ERROR: Unexpected error"

def parse_int64(token: str) -> int:
    token = token.strip()
    if not token or any(ch.isspace() for ch in token):
        raise ValueError("Invalid")
    if not is_valid_int_token(token):
        raise ValueError("Invalid")
    val = int(token, 10)
    if val < MIN_INT64 or val > MAX_INT64:
        raise ValueError("Invalid")
    return val

def is_valid_int_token(t: str) -> bool:
    if t[0] in "+-":
        return len(t) > 1 and t[1:].isdigit()
    return t.isdigit()

def within64(x: int) -> bool:
    return MIN_INT64 <= x <= MAX_INT64

def checked_result(x: int) -> str:
    if not within64(x):
        return "ERROR: Overflow"
    return f"RESULT: {x}"

def trunc_div(a: int, b: int) -> int:
    sign = -1 if (a < 0) ^ (b < 0) else 1
    return sign * (abs(a) // abs(b))

def mul_overflow(a: int, b: int) -> bool:
    # Fast checks
    if a == 0 or b == 0:
        return False
    # Special case
    if a == MIN_INT64 and b == -1:
        return True
    if b == MIN_INT64 and a == -1:
        return True
    return not within64(a * b)

def pow_checked(base: int, exp: int) -> int:
    result = 1
    b = base
    e = exp
    while e > 0:
        if e & 1:
            if mul_overflow(result, b):
                raise OverflowError
            result *= b
        e >>= 1
        if e > 0:
            if mul_overflow(b, b):
                raise OverflowError
            b *= b
    return result

def main():
    tests = [
        "ADD 3 5",
        "DIV 10 0",
        "POW 2 10",
        "MUL 9223372036854775807 2",
        "SUB a 5",
    ]
    for t in tests:
        out = process_input(t)
        print(f"Input: {t} -> {out}")

if __name__ == "__main__":
    main()