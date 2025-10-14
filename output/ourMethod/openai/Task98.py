from dataclasses import dataclass
from typing import Tuple

MAX_LEN = 64
INT_MIN = -2147483648
INT_MAX = 2147483647

@dataclass
class ParseResult:
    success: bool
    value: int
    error: str

def parse_int_strict(s: str) -> ParseResult:
    if s is None:
        return ParseResult(False, 0, "Input is null")

    trimmed = s.strip()
    if len(trimmed) == 0:
        return ParseResult(False, 0, "Empty input")
    if len(trimmed) > MAX_LEN:
        return ParseResult(False, 0, "Input too long")

    idx = 0
    negative = False
    first = trimmed[0]
    if first in "+-":
        negative = (first == "-")
        idx += 1
        if idx >= len(trimmed):
            return ParseResult(False, 0, "No digits after sign")

    acc = 0
    for c in trimmed[idx:]:
        if c < '0' or c > '9':
            return ParseResult(False, 0, "Invalid character encountered")
        d = ord(c) - ord('0')
        acc = acc * 10 + d
        limit = -INT_MIN if negative else INT_MAX
        if acc > limit:
            return ParseResult(False, 0, "Integer out of range")

    signed_val = -acc if negative else acc
    if signed_val < INT_MIN or signed_val > INT_MAX:
        return ParseResult(False, 0, "Integer out of range")
    return ParseResult(True, int(signed_val), "")

def main() -> None:
    try:
        for i in range(1, 6):
            try:
                line = input(f"Enter value #{i}: ")
            except EOFError:
                print("No more input.")
                break
            res = parse_int_strict(line)
            if res.success:
                print(f"Parsed integer: {res.value}")
            else:
                print(f"Error: {res.error}")
    except Exception as e:
        print(f"Runtime error: {str(e)}")

if __name__ == "__main__":
    main()