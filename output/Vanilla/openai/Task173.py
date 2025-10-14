def longest_dup_substring(s: str) -> str:
    n = len(s)
    if n <= 1:
        return ""
    vals = [ord(c) - 96 for c in s]  # 'a' -> 1

    MOD1 = 1_000_000_007
    MOD2 = 1_000_000_009
    BASE1 = 911_382_323 % MOD1
    BASE2 = 972_663_749 % MOD2

    pow1 = [1] * (n + 1)
    pow2 = [1] * (n + 1)
    pref1 = [0] * (n + 1)
    pref2 = [0] * (n + 1)
    for i in range(n):
        pow1[i + 1] = (pow1[i] * BASE1) % MOD1
        pow2[i + 1] = (pow2[i] * BASE2) % MOD2
        pref1[i + 1] = (pref1[i] * BASE1 + vals[i]) % MOD1
        pref2[i + 1] = (pref2[i] * BASE2 + vals[i]) % MOD2

    def get_hash(pref, pow_arr, mod, i, L):
        return (pref[i + L] - (pref[i] * pow_arr[L]) % mod + mod) % mod

    def check(L):
        if L == 0:
            return 0
        seen = {}
        for i in range(0, n - L + 1):
            h1 = get_hash(pref1, pow1, MOD1, i, L)
            h2 = get_hash(pref2, pow2, MOD2, i, L)
            key = (h1 << 32) ^ h2
            if key in seen:
                return i
            seen[key] = i
        return -1

    lo, hi = 1, n - 1
    best_len, best_idx = 0, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        idx = check(mid)
        if idx != -1:
            best_len, best_idx = mid, idx
            lo = mid + 1
        else:
            hi = mid - 1
    return "" if best_idx == -1 else s[best_idx:best_idx + best_len]


if __name__ == "__main__":
    tests = ["banana", "abcd", "aaaaa", "abcabc", "mississippi"]
    for t in tests:
        print("Input:", t)
        print("Output:", longest_dup_substring(t))
        print()