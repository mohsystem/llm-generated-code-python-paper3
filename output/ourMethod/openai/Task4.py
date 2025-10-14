from typing import List

def is_isogram(s: str) -> bool:
    if not isinstance(s, str):
        return False  # fail closed
    seen: List[bool] = [False] * 26
    for ch in s:
        if 'A' <= ch <= 'Z':
            ch = chr(ord(ch) + (ord('a') - ord('A')))
        elif not ('a' <= ch <= 'z'):
            return False  # invalid character
        idx = ord(ch) - ord('a')
        if seen[idx]:
            return False
        seen[idx] = True
    return True

if __name__ == "__main__":
    tests = [
        "Dermatoglyphics",
        "aba",
        "moOse",
        "",
        "isogram"
    ]
    for t in tests:
        print(f"\"{t}\" -> {is_isogram(t)}")