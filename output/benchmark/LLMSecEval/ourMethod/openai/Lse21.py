import re
import sys
from typing import Optional

MIN_I64 = -(1 << 63)
MAX_I64 = (1 << 63) - 1

def add_1000(value: int) -> int:
    # Ensure result fits in signed 64-bit range
    if value > MAX_I64 - 1000:
        raise OverflowError("overflow")
    return value + 1000

def parse_int64(arg: str) -> Optional[int]:
    s = arg.strip()
    if not re.fullmatch(r"[+-]?\d{1,19}", s):
        return None
    try:
        n = int(s, 10)
    except ValueError:
        return None
    if n < MIN_I64 or n > MAX_I64:
        return None
    return n

def main() -> int:
    if len(sys.argv) > 1:
        n = parse_int64(sys.argv[1])
        if n is None:
            print("Invalid input", file=sys.stderr)
            return 1
        try:
            result = add_1000(n)
        except OverflowError:
            print("Invalid input", file=sys.stderr)
            return 1
        print(result)
        return 0
    else:
        # 5 test cases
        tests = [
            0,
            1,
            -1000,
            123456789012345,
            MAX_I64 - 1000,
        ]
        for t in tests:
            try:
                print(add_1000(t))
            except OverflowError:
                print("overflow")
        return 0

if __name__ == "__main__":
    sys.exit(main())