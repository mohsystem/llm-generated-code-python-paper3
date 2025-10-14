from typing import List, Tuple, Dict

def longest_dup_substring(s: str) -> str:
    if not isinstance(s, str):
        return ""
    n = len(s)
    if n < 2 or n > 30000:
        return ""
    if any(not ('a' <= ch <= 'z') for ch in s):
        return ""

    mod1 = 1_000_000_007
    mod2 = 1_000_000_009
    base1 = 911_382_323
    base2 = 972_663_749

    pow1 = [1] * (n + 1)
    pow2 = [1] * (n + 1)
    pre1 = [0] * (n + 1)
    pre2 = [0] * (n + 1)
    for i, ch in enumerate(s):
        v = ord(ch) - 96  # 'a' -> 1
        pre1[i + 1] = (pre1[i] * base1 + v) % mod1
        pre2[i + 1] = (pre2[i] * base2 + v) % mod2
        pow1[i + 1] = (pow1[i] * base1) % mod1
        pow2[i + 1] = (pow2[i] * base2) % mod2

    def check(L: int) -> int:
        if L <= 0:
            return -1
        seen: Dict[Tuple[int, int], List[int]] = {}
        for i in range(0, n - L + 1):
            h1 = (pre1[i + L] - (pre1[i] * pow1[L]) % mod1 + mod1) % mod1
            h2 = (pre2[i + L] - (pre2[i] * pow2[L]) % mod2 + mod2) % mod2
            key = (h1, h2)
            if key not in seen:
                seen[key] = [i]
            else:
                for prev in seen[key]:
                    # verify to avoid hash collisions
                    if s[prev:prev + L] == s[i:i + L]:
                        return i
                seen[key].append(i)
        return -1

    lo, hi = 1, n - 1
    best_start, best_len = -1, 0
    while lo <= hi:
        mid = (lo + hi) // 2
        idx = check(mid)
        if idx != -1:
            best_start, best_len = idx, mid
            lo = mid + 1
        else:
            hi = mid - 1
    return "" if best_start == -1 else s[best_start:best_start + best_len]

if __name__ == "__main__":
    tests = [
        "banana",
        "abcd",
        "aaaaa",
        "abcabcabc",
        "mississippi",
    ]
    for t in tests:
        print(f"Input: {t} -> Output: {longest_dup_substring(t)}")