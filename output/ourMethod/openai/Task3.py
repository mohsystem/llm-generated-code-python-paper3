from typing import List

ALPHABET_MASK: int = (1 << 26) - 1
MAX_LEN: int = 5_000_000

def is_pangram(s: str) -> bool:
    if not isinstance(s, str):
        return False
    if len(s) > MAX_LEN:
        return False

    mask = 0
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:  # 'A'..'Z'
            o += 32        # to lowercase
        if 97 <= o <= 122:  # 'a'..'z'
            mask |= 1 << (o - 97)
            if mask == ALPHABET_MASK:
                return True
    return mask == ALPHABET_MASK

def main() -> None:
    tests: List[str] = [
        "The quick brown fox jumps over the lazy dog",
        "Sphinx of black quartz, judge my vow",
        "Hello, World!",
        "Pack my box with five dozen liquor jugs.",
        "",
    ]
    for t in tests:
        print(is_pangram(t))

if __name__ == "__main__":
    main()