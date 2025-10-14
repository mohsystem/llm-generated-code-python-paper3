import sys

MOD1 = 1_000_000_007
MOD2 = 1_000_000_009
BASE1 = 911_382_323
BASE2 = 972_663_749

def _build_hash(s: str):
    n = len(s)
    h1 = [0] * (n + 1)
    h2 = [0] * (n + 1)
    p1 = [1] * (n + 1)
    p2 = [1] * (n + 1)
    for i, ch in enumerate(s):
        v = ord(ch) - 96
        h1[i + 1] = (h1[i] * BASE1 + v) % MOD1
        h2[i + 1] = (h2[i] * BASE2 + v) % MOD2
        p1[i + 1] = (p1[i] * BASE1) % MOD1
        p2[i + 1] = (p2[i] * BASE2) % MOD2
    return h1, h2, p1, p2

def _get(h1, h2, p1, p2, l, r):
    x1 = (h1[r] - (h1[l] * p1[r - l]) % MOD1) % MOD1
    x2 = (h2[r] - (h2[l] * p2[r - l]) % MOD2) % MOD2
    return x1, x2

def count_square_substrings(text: str) -> int:
    if text is None:
        return 0
    n = len(text)
    if n <= 1:
        return 0
    h1, h2, p1, p2 = _build_hash(text)
    seen = set()
    for L in range(2, n + 1, 2):
        for i in range(0, n - L + 1):
            mid = i + L // 2
            a1, a2 = _get(h1, h2, p1, p2, i, mid)
            b1, b2 = _get(h1, h2, p1, p2, mid, i + L)
            if a1 == b1 and a2 == b2:
                f1, f2 = _get(h1, h2, p1, p2, i, i + L)
                seen.add((f1, f2, L))
    return len(seen)

if __name__ == "__main__":
    tests = [
        "abcabcabc",
        "leetcodeleetcode",
        "aaaaaa",
        "abcd",
        "abbaabba",
    ]
    for t in tests:
        print(count_square_substrings(t))