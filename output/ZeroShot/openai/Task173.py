def longest_dup_substring(s: str) -> str:
    if s is None or len(s) < 2:
        return ""
    n = len(s)
    sa = build_suffix_array(s)
    lcp = build_lcp(s, sa)
    max_l = 0
    pos = -1
    for i in range(n - 1):
        if lcp[i] > max_l:
            max_l = lcp[i]
            pos = sa[i]
    return "" if max_l == 0 else s[pos:pos + max_l]

def build_suffix_array(s: str):
    n = len(s)
    sa = list(range(n))
    rnk = [ord(c) - ord('a') for c in s]
    tmp = [0] * n

    key1 = [0] * n
    key2 = [0] * n
    out = [0] * n

    k = 1
    while k < n:
        max_rank = max(rnk) if rnk else 0
        for i in range(n):
            key2[i] = (rnk[i + k] + 1) if (i + k < n) else 0
        counting_sort(sa, key2, max_rank + 2, out)

        for i in range(n):
            key1[i] = rnk[i] + 1
        counting_sort(out, key1, max_rank + 2, sa)

        tmp[sa[0]] = 0
        classes = 1
        for i in range(1, n):
            cur, prev = sa[i], sa[i - 1]
            if rnk[cur] != rnk[prev] or key2[cur] != key2[prev]:
                classes += 1
            tmp[cur] = classes - 1
        rnk, tmp = tmp, rnk
        if classes == n:
            break
        k <<= 1
    return sa

def counting_sort(sa_in, key, max_key, sa_out):
    n = len(sa_in)
    cnt = [0] * (max_key + 1)
    for idx in sa_in:
        cnt[key[idx]] += 1
    total = 0
    for i in range(max_key + 1):
        cnt[i], total = total, total + cnt[i]
    for idx in sa_in:
        k = key[idx]
        sa_out[cnt[k]] = idx
        cnt[k] += 1

def build_lcp(s, sa):
    n = len(s)
    rank = [0] * n
    for i, p in enumerate(sa):
        rank[p] = i
    lcp = [0] * (n - 1)
    k = 0
    for i in range(n):
        r = rank[i]
        if r == n - 1:
            k = 0
            continue
        j = sa[r + 1]
        while i + k < n and j + k < n and s[i + k] == s[j + k]:
            k += 1
        lcp[r] = k
        if k:
            k -= 1
    return lcp

if __name__ == "__main__":
    tests = [
        "banana",
        "abcd",
        "aaaaa",
        "abcabca",
        "mississippi"
    ]
    for t in tests:
        print(f"Input: {t} -> Output: {longest_dup_substring(t)}")