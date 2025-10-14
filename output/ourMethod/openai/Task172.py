from typing import Tuple, Set

MASK = (1 << 64) - 1
BASE1 = 11400714819323198485  # random odd 64-bit
BASE2 = 14029467366897019727  # another random odd 64-bit

def _validate(text: str) -> None:
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    n = len(text)
    if n < 1 or n > 2000:
        raise ValueError("length out of range")
    for c in text:
        if c < 'a' or c > 'z':
            raise ValueError("invalid character")

def _build_hashes(s: str):
    n = len(s)
    pow1 = [0] * (n + 1)
    pow2 = [0] * (n + 1)
    h1 = [0] * (n + 1)
    h2 = [0] * (n + 1)
    pow1[0] = 1
    pow2[0] = 1
    for i in range(1, n + 1):
        pow1[i] = (pow1[i - 1] * BASE1) & MASK
        pow2[i] = (pow2[i - 1] * BASE2) & MASK
    for i, ch in enumerate(s, 1):
        v = ord(ch) - 96
        h1[i] = (h1[i - 1] * BASE1 + v) & MASK
        h2[i] = (h2[i - 1] * BASE2 + v) & MASK
    return pow1, pow2, h1, h2

def _get_hash(h, pow_arr, l: int, r: int) -> int:
    # [l, r)
    return (h[r] - (h[l] * pow_arr[r - l] & MASK)) & MASK

def count_square_substrings_distinct(text: str) -> int:
    _validate(text)
    n = len(text)
    if n < 2:
        return 0
    pow1, pow2, h1, h2 = _build_hashes(text)
    seen: Set[Tuple[int, int, int]] = set()
    for i in range(n):
        L = 2
        while i + L <= n:
            mid = i + (L >> 1)
            a1 = _get_hash(h1, pow1, i, mid)
            b1 = _get_hash(h1, pow1, mid, i + L)
            if a1 == b1:
                a2 = _get_hash(h2, pow2, i, mid)
                b2 = _get_hash(h2, pow2, mid, i + L)
                if a2 == b2:
                    hh1 = _get_hash(h1, pow1, i, i + L)
                    hh2 = _get_hash(h2, pow2, i, i + L)
                    seen.add((hh1, hh2, L))
            L += 2
    return len(seen)

if __name__ == "__main__":
    tests = [
        "abcabcabc",         # 3
        "leetcodeleetcode",  # 2
        "aaaaaa",            # 3
        "ababab",            # 2
        "a"                  # 0
    ]
    for t in tests:
        print(f"Input: {t} -> {count_square_substrings_distinct(t)}")