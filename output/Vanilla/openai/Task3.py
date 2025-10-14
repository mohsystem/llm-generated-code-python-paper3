def is_pangram(s: str) -> bool:
    seen = [False] * 26
    count = 0
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            o += 32
        if 97 <= o <= 122:
            idx = o - 97
            if not seen[idx]:
                seen[idx] = True
                count += 1
                if count == 26:
                    return True
    return count == 26

if __name__ == "__main__":
    tests = [
        "The quick brown fox jumps over the lazy dog",
        "Sphinx of black quartz, judge my vow",
        "Hello, World!",
        "",
        "Pack my box with five dozen liquor jugs."
    ]
    for t in tests:
        print(is_pangram(t))