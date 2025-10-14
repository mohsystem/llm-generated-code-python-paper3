import sys
from typing import Optional

MAX_LEN = 64

def parse_to_int(s: str) -> Optional[int]:
    if s is None:
        return None
    t = s.strip()
    if not t or len(t) > MAX_LEN:
        return None

    i = 0
    n = len(t)
    negative = False

    if t[0] == '-':
        negative = True
        i = 1
    elif t[0] == '+':
        i = 1

    if i == n:
        return None

    limit = -2_147_483_648 if negative else -2_147_483_647
    multmin = limit // 10
    result = 0

    while i < n:
        ch = t[i]
        if ch < '0' or ch > '9':
            return None
        digit = ord(ch) - ord('0')
        if result < multmin:
            return None
        result *= 10
        if result < limit + digit:
            return None
        result -= digit
        i += 1

    return result if negative else -result

if __name__ == "__main__":
    inputs = sys.argv[1:] if len(sys.argv) > 1 else ["123", "-42", "00123", "2147483648", "abc123"]
    for s in inputs:
        val = parse_to_int(s)
        if val is not None:
            print(f'Input: "{s}" -> OK: {val}')
        else:
            print(f'Input: "{s}" -> Invalid integer')