from typing import List

MAX_LEN: int = 10000

def accum(s: str) -> str:
    if not isinstance(s, str):
        raise ValueError("Input must be a string.")
    n = len(s)
    if n > MAX_LEN:
        raise ValueError("Input too long.")
    for ch in s:
        if not (('A' <= ch <= 'Z') or ('a' <= ch <= 'z')):
            raise ValueError("Input must contain only ASCII letters [A-Za-z].")
    parts: List[str] = []
    for i, ch in enumerate(s):
        upper = ch.upper()
        lower = ch.lower()
        parts.append(upper + lower * i)
    return "-".join(parts)

if __name__ == "__main__":
    tests = ["abcd", "RqaEzty", "cwAt", "Z", "abc1"]  # last is invalid
    for t in tests:
        try:
            print(accum(t))
        except ValueError as e:
            print(f"ERROR: {e}")