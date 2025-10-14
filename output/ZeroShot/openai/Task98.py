import sys
import re

INT_PATTERN = re.compile(r'^[+-]?\d+$')
LL_MIN = -(1 << 63)
LL_MAX = (1 << 63) - 1

def try_parse_int(s: str):
    if s is None:
        return (False, 0)
    t = s.strip()
    if not t or not INT_PATTERN.fullmatch(t):
        return (False, 0)
    try:
        val = int(t, 10)
    except Exception:
        return (False, 0)
    if val < LL_MIN or val > LL_MAX:
        return (False, 0)
    return (True, val)

def main():
    line = sys.stdin.readline()
    if line:
        ok, val = try_parse_int(line)
        if ok:
            print(f"Parsed integer: {val}")
        else:
            print("Invalid integer input.")
    else:
        print("No input provided.")

    tests = [
        "123",
        "   -456   ",
        "+789",
        "9223372036854775808",
        "abc123",
    ]
    for t in tests:
        ok, val = try_parse_int(t)
        if ok:
            print(f'Test "{t}" -> {val}')
        else:
            print(f'Test "{t}" -> invalid')

if __name__ == "__main__":
    main()