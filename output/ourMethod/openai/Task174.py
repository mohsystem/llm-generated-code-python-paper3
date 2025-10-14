from typing import List

def shortest_palindrome(s: str) -> str:
    if not isinstance(s, str):
        return ""
    n = len(s)
    if n > 50000:
        return ""
    for ch in s:
        if not ('a' <= ch <= 'z'):
            return ""
    if n <= 1:
        return s
    rev = s[::-1]
    combined = s + "#" + rev
    lps = _build_lps(combined)
    l = lps[-1]
    add = rev[:n - l]
    return add + s

def _build_lps(t: str) -> List[int]:
    lps = [0] * len(t)
    j = 0
    for i in range(1, len(t)):
        while j > 0 and t[i] != t[j]:
            j = lps[j - 1]
        if t[i] == t[j]:
            j += 1
        lps[i] = j
    return lps

if __name__ == "__main__":
    tests = [
        "aacecaaa",
        "abcd",
        "",
        "a",
        "aaab",
    ]
    for t in tests:
        res = shortest_palindrome(t)
        print(f'Input: "{t}" -> Output: "{res}"')