from typing import Optional

MIN_VAL = -1_000_000_000
MAX_VAL = 1_000_000_000
MAX_INPUT_LEN = 100
LL_MIN = -(1 << 63)
LL_MAX = (1 << 63) - 1

def _is_upper_alpha(s: str) -> bool:
    return 1 <= len(s) <= 10 and s.isalpha() and s.isupper()

def _parse_int(s: str) -> Optional[int]:
    if not (1 <= len(s) <= 20):
        return None
    try:
        # Safe parsing without eval
        v = int(s, 10)
        return v
    except Exception:
        return None

def _safe_add(a: int, b: int) -> Optional[int]:
    r = a + b
    if r < LL_MIN or r > LL_MAX:
        return None
    return r

def _safe_sub(a: int, b: int) -> Optional[int]:
    r = a - b
    if r < LL_MIN or r > LL_MAX:
        return None
    return r

def _safe_mul(a: int, b: int) -> Optional[int]:
    # Use Python big ints then check bounds
    r = a * b
    if r < LL_MIN or r > LL_MAX:
        return None
    return r

def _safe_pow(base: int, exp: int) -> Optional[int]:
    result = 1
    b = base
    e = exp
    while e > 0:
        if e & 1:
            tmp = _safe_mul(result, b)
            if tmp is None:
                return None
            result = tmp
        e >>= 1
        if e:
            tmp2 = _safe_mul(b, b)
            if tmp2 is None:
                return None
            b = tmp2
    return result

def process_command(input_str: str) -> str:
    try:
        if input_str is None:
            return "ERROR: input is null"
        raw_bytes = input_str.encode("utf-8", errors="strict")
        if len(raw_bytes) == 0 or len(raw_bytes) > MAX_INPUT_LEN:
            return "ERROR: input length out of allowed range (1..100 bytes)"
        parts = input_str.strip().split()
        if len(parts) != 3:
            return "ERROR: expected format '<OP> <A> <B>' with exactly 3 tokens"
        op, a_s, b_s = parts
        if not _is_upper_alpha(op):
            return "ERROR: operation must be uppercase letters only"
        if op not in {"ADD", "SUB", "MUL", "DIV", "MOD", "POW"}:
            return "ERROR: unsupported operation"
        a = _parse_int(a_s)
        b = _parse_int(b_s)
        if a is None or b is None:
            return "ERROR: operands must be valid 64-bit integers"
        if not (MIN_VAL <= a <= MAX_VAL) or not (MIN_VAL <= b <= MAX_VAL):
            return "ERROR: operands out of allowed range [-1000000000, 1000000000]"
        if op == "ADD":
            r = _safe_add(a, b)
            if r is None:
                return "ERROR: addition overflow"
        elif op == "SUB":
            r = _safe_sub(a, b)
            if r is None:
                return "ERROR: subtraction overflow"
        elif op == "MUL":
            r = _safe_mul(a, b)
            if r is None:
                return "ERROR: multiplication overflow"
        elif op == "DIV":
            if b == 0:
                return "ERROR: division by zero"
            # Check overflow case
            if a == LL_MIN and b == -1:
                return "ERROR: division overflow"
            r = int(a // b)
        elif op == "MOD":
            if b == 0:
                return "ERROR: modulo by zero"
            r = int(a % b)
        else:  # POW
            if b < 0:
                return "ERROR: negative exponent not supported"
            if b > 62:
                return "ERROR: exponent too large"
            r = _safe_pow(a, b)
            if r is None:
                return "ERROR: power overflow"
        return f"OK result: {r}"
    except Exception:
        return "ERROR: unexpected failure"

def _main() -> None:
    tests = [
        "ADD 3 5",
        "DIV 10 0",
        "MUL 123456 789",
        "POW 2 10",
        "XYZ 1 2",
    ]
    for t in tests:
        try:
            out = process_command(t)
            print(f"Input: '{t}' -> {out}")
        except Exception:
            print(f"Input: '{t}' -> ERROR: unexpected failure")

if __name__ == "__main__":
    _main()