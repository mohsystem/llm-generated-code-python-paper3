def is_pangram(s: str) -> bool:
    if s is None:
        return False
    mask = 0
    full = (1 << 26) - 1
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            o += 32
        if 97 <= o <= 122:
            mask |= 1 << (o - 97)
            if mask == full:
                break
    return mask == full

if __name__ == "__main__":
    tests = [
        "The quick brown fox jumps over the lazy dog",
        "Hello, World!",
        "",
        "Pack my box with five dozen liquor jugs.",
        "The quick brown fox jumps over the lay dog"
    ]
    for t in tests:
        print("True" if is_pangram(t) else "False")