from typing import Tuple, Optional, List
import sys

def convert_to_int(s: str) -> Tuple[bool, Optional[int], Optional[str]]:
    if s is None:
        return (False, None, "null input")
    s = s.strip()
    if not s:
        return (False, None, "empty input")

    sign = 1
    idx = 0
    if s[0] in ['+', '-']:
        sign = -1 if s[0] == '-' else 1
        idx += 1

    if idx >= len(s):
        return (False, None, "no digits")

    acc = 0
    INT_MAX = 2147483647
    INT_MIN = -2147483648
    limit = INT_MAX if sign == 1 else -INT_MIN  # 2147483648 for negative

    for i in range(idx, len(s)):
        c = s[i]
        if c < '0' or c > '9':
            return (False, None, f"invalid character at position {i}")
        digit = ord(c) - ord('0')
        if acc > (limit - digit) // 10:
            return (False, None, "overflow")
        acc = acc * 10 + digit

    value = acc if sign == 1 else -acc
    # value is guaranteed to be within 32-bit signed range due to checks
    return (True, int(value), None)

def main():
    args: List[str] = sys.argv[1:]
    inputs = args if args else ["123", "-42", "2147483647", "-2147483648", "99abc"]
    for s in inputs:
        ok, val, err = convert_to_int(s)
        if ok:
            print(f'Input: "{s}" -> OK {val}')
        else:
            print(f'Input: "{s}" -> ERROR {err}')

if __name__ == "__main__":
    main()