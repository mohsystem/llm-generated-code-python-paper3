def longestDupSubstring(s: str) -> str:
    n = len(s)
    if n < 2:
        return ""
    MOD1 = 1_000_000_007
    MOD2 = 1_000_000_009
    BASE = 911382323  # fixed base < both mods

    pow1 = [1] * (n + 1)
    pow2 = [1] * (n + 1)
    pre1 = [0] * (n + 1)
    pre2 = [0] * (n + 1)
    for i, ch in enumerate(s):
        v = ord(ch) - 96
        pow1[i + 1] = (pow1[i] * BASE) % MOD1
        pow2[i + 1] = (pow2[i] * BASE) % MOD2
        pre1[i + 1] = (pre1[i] * BASE + v) % MOD1
        pre2[i + 1] = (pre2[i] * BASE + v) % MOD2

    def get_key(l: int, L: int):
        r = l + L
        h1 = (pre1[r] - pre1[l] * pow1[L]) % MOD1
        h2 = (pre2[r] - pre2[l] * pow2[L]) % MOD2
        return (h1, h2)

    def check(L: int) -> int:
        if L == 0:
            return 0
        table = {}
        for i in range(0, n - L + 1):
            key = get_key(i, L)
            if key in table:
                for j in table[key]:
                    if s[i:i+L] == s[j:j+L]:
                        return i
                table[key].append(i)
            else:
                table[key] = [i]
        return -1

    lo, hi = 1, n - 1
    best_len, best_start = 0, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        pos = check(mid)
        if pos != -1:
            best_len, best_start = mid, pos
            lo = mid + 1
        else:
            hi = mid - 1
    return s[best_start:best_start + best_len] if best_len > 0 else ""

if __name__ == "__main__":
    tests = [
        "banana",
        "abcd",
        "aaaaa",
        "abcdabc",
        "mississippi",
    ]
    for t in tests:
        print(f"Input: {t} -> Output: {longestDupSubstring(t)}")