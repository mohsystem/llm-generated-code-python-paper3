MOD1 = 1_000_000_007
MOD2 = 1_000_000_009
BASE1 = 911_382_323
BASE2 = 972_663_749

def count_square_distinct_substrings(s: str) -> int:
    n = len(s)
    pow1 = [1] * (n + 1)
    pow2 = [1] * (n + 1)
    for i in range(1, n + 1):
        pow1[i] = (pow1[i - 1] * BASE1) % MOD1
        pow2[i] = (pow2[i - 1] * BASE2) % MOD2
    pref1 = [0] * (n + 1)
    pref2 = [0] * (n + 1)
    for i, ch in enumerate(s):
        v = ord(ch) - 96
        pref1[i + 1] = (pref1[i] * BASE1 + v) % MOD1
        pref2[i + 1] = (pref2[i] * BASE2 + v) % MOD2

    def get_hash(pref, pow_arr, mod, l, r):
        res = (pref[r + 1] - (pref[l] * pow_arr[r - l + 1]) % mod) % mod
        return res

    seen = set()
    for l in range(n):
        length = 2
        while l + length <= n:
            mid = l + length // 2
            r = l + length - 1
            if (get_hash(pref1, pow1, MOD1, l, mid - 1) == get_hash(pref1, pow1, MOD1, mid, r) and
                get_hash(pref2, pow2, MOD2, l, mid - 1) == get_hash(pref2, pow2, MOD2, mid, r)):
                hs1 = get_hash(pref1, pow1, MOD1, l, r)
                hs2 = get_hash(pref2, pow2, MOD2, l, r)
                seen.add((hs1 << 32) ^ hs2)
            length += 2
    return len(seen)

if __name__ == "__main__":
    tests = [
        "abcabcabc",
        "leetcodeleetcode",
        "aaaa",
        "abab",
        "xyz",
    ]
    for t in tests:
        print(count_square_distinct_substrings(t))