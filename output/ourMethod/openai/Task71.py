from typing import List
import sys

def try_parse_int(s: str) -> str:
    if s is None:
        return "ERROR: null input"
    s2 = s.strip()
    if len(s2) < 1 or len(s2) > 64:
        return "ERROR: input length out of range (1..64)"

    idx = 0
    sign = 1
    if s2[0] in ('+', '-'):
        sign = -1 if s2[0] == '-' else 1
        idx += 1
    if idx >= len(s2):
        return "ERROR: no digits found"

    value = 0
    INT_MAX = 2147483647
    LIMIT_NEG = 2147483648  # magnitude allowed for negative numbers

    for ch in s2[idx:]:
        if ch < '0' or ch > '9':
            return "ERROR: non-digit character encountered"
        d = ord(ch) - ord('0')
        if sign == 1:
            if value > (INT_MAX - d) // 10:
                return "ERROR: integer overflow"
        else:
            if value > (LIMIT_NEG - d) // 10:
                return "ERROR: integer underflow"
        value = value * 10 + d

    result = value if sign == 1 else -value
    return f"OK: {result}"

def main() -> None:
    inputs: List[str] = sys.argv[1:] if len(sys.argv) > 1 else [
        "123", "-42", "0042", "2147483648", "12a"
    ]
    for inp in inputs:
        res = try_parse_int(inp)
        print(f'Input: "{inp}" -> {res}')

if __name__ == "__main__":
    main()