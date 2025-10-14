def is_isogram(s: str) -> bool:
    if not isinstance(s, str):
        return False
    n = len(s)
    if n == 0:
        return True
    if n > 26:
        return False  # Pigeonhole principle for English alphabet

    mask = 0
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:  # 'A'-'Z'
            o += 32        # to lowercase
        elif not (97 <= o <= 122):  # 'a'-'z'
            return False
        idx = o - 97
        bit = 1 << idx
        if (mask & bit) != 0:
            return False
        mask |= bit
    return True

if __name__ == "__main__":
    tests = [
        "Dermatoglyphics",
        "aba",
        "moOse",
        "",
        "isogram",
    ]
    for t in tests:
        print(f"{t} -> {is_isogram(t)}")