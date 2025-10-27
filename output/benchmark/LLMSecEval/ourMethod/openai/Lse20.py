import sys
from typing import Tuple

OFFSET: int = 1000
INT64_MIN: int = -2**63
INT64_MAX: int = 2**63 - 1

def add_offset(value: int) -> int:
    if value > INT64_MAX - OFFSET:
        raise OverflowError("overflow")
    return value + OFFSET

def try_parse_int64(s: str) -> Tuple[bool, int]:
    if s is None:
        return False, 0
    t = s.strip()
    if not t:
        return False, 0
    if len(t) > 20:  # optional sign + up to 19 digits
        return False, 0
    if t[0] in "+-":
        if len(t) == 1 or not t[1:].isdigit():
            return False, 0
    else:
        if not t.isdigit():
            return False, 0
    try:
        v = int(t, 10)
    except ValueError:
        return False, 0
    if v < INT64_MIN or v > INT64_MAX:
        return False, 0
    return True, v

def main() -> None:
    if len(sys.argv) >= 2:
        ok, val = try_parse_int64(sys.argv[1])
        if not ok:
            print("Invalid input", file=sys.stderr)
            sys.exit(1)
        try:
            res = add_offset(val)
        except OverflowError:
            print("Overflow", file=sys.stderr)
            sys.exit(1)
        print(res)
    else:
        # 5 test cases
        tests = [0, 42, -1000, INT64_MAX - OFFSET, INT64_MIN + OFFSET]
        for v in tests:
            try:
                print(add_offset(v))
            except OverflowError:
                print("Overflow")

if __name__ == "__main__":
    main()