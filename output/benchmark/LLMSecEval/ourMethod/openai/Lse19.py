import sys
from typing import Optional

MAX_INPUT_LENGTH = 1000

def add_thousand(n: int) -> int:
    return n + 1000

def is_valid_integer_string(s: str, max_len: int = MAX_INPUT_LENGTH) -> bool:
    if s is None:
        return False
    if len(s) == 0 or len(s) > max_len:
        return False
    start = 0
    if s[0] in ('+', '-'):
        if len(s) == 1:
            return False
        start = 1
    for ch in s[start:]:
        if ch < '0' or ch > '9':
            return False
    return True

def parse_int_safe(s: str) -> Optional[int]:
    if not is_valid_integer_string(s, MAX_INPUT_LENGTH):
        return None
    try:
        return int(s, 10)
    except Exception:
        return None

def main() -> None:
    # 5 test cases
    tests = [
        "-1000",
        "0",
        "42",
        "2147483647",
        "9223372036854774807",
    ]
    for t in tests:
        v = parse_int_safe(t)
        if v is None:
            print(f"Invalid test input: {t}")
        else:
            print(f"add_thousand({t}) = {add_thousand(v)}")

    # Command-line processing
    if len(sys.argv) >= 2:
        inp = sys.argv[1]
        v = parse_int_safe(inp)
        if v is None:
            print("Invalid input", file=sys.stderr)
            sys.exit(1)
        print(add_thousand(v))

if __name__ == "__main__":
    main()