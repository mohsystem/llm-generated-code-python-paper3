from typing import List, Tuple

MOD1 = 1_000_000_007
MOD2 = 1_000_000_009
BASE1 = 911_382_323
BASE2 = 972_663_749

def count_even_square_distinct(text: str) -> int:
    if text is None:
        return 0
    n = len(text)
    if n <= 1:
        return 0

    pow1 = [1] * (n + 1)
    pow2 = [1] * (n + 1)
    pref1 = [0] * (n + 1)
    pref2 = [0] * (n + 1)

    for i, ch in enumerate(text):
        v = ord(ch) - 96
        pref1[i + 1] = (pref1[i] * BASE1 + v) % MOD1
        pref2[i + 1] = (pref2[i] * BASE2 + v) % MOD2
        pow1[i + 1] = (pow1[i] * BASE1) % MOD1
        pow2[i + 1] = (pow2[i] * BASE2) % MOD2

    def sub_hash(pref, powa, l, r, mod):
        res = (pref[r + 1] - (pref[l] * powa[r - l + 1]) % mod) % mod
        return res

    seen = set()
    for length in range(2, n + 1, 2):
        half = length // 2
        for i in range(0, n - length + 1):
            mid = i + half
            j = i + length - 1
            a1 = sub_hash(pref1, pow1, i, mid - 1, MOD1)
            b1 = sub_hash(pref1, pow1, mid, j, MOD1)
            if a1 != b1:
                continue
            a2 = sub_hash(pref2, pow2, i, mid - 1, MOD2)
            b2 = sub_hash(pref2, pow2, mid, j, MOD2)
            if a2 != b2:
                continue
            h1 = sub_hash(pref1, pow1, i, j, MOD1)
            h2 = sub_hash(pref2, pow2, i, j, MOD2)
            seen.add((h1, h2, length))
    return len(seen)

if __name__ == "__main__":
    tests = [
        "abcabcabc",
        "leetcodeleetcode",
        "aaaa",
        "ababa",
        "z",
    ]
    for t in tests:
        print(count_even_square_distinct(t))