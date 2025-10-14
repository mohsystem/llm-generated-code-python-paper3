def is_isogram(s: str) -> bool:
    mask = 0
    for ch in s.lower():
        if 'a' <= ch <= 'z':
            bit = ord(ch) - ord('a')
            if mask & (1 << bit):
                return False
            mask |= 1 << bit
    return True

if __name__ == "__main__":
    tests = ["Dermatoglyphics", "aba", "moOse", "", "isogram"]
    for t in tests:
        print(f"{t} -> {str(is_isogram(t)).lower()}")