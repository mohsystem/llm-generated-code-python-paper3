def shortest_palindrome(s: str) -> str:
    if s is None or len(s) <= 1:
        return "" if s is None else s
    rev = s[::-1]
    pattern = s + "#" + rev
    lps = [0] * len(pattern)
    length = 0
    i = 1
    while i < len(pattern):
        if pattern[i] == pattern[length]:
            length += 1
            lps[i] = length
            i += 1
        elif length != 0:
            length = lps[length - 1]
        else:
            lps[i] = 0
            i += 1
    pal_len = lps[-1]
    suffix = s[pal_len:]
    return suffix[::-1] + s


if __name__ == "__main__":
    tests = [
        "aacecaaa",
        "abcd",
        "",
        "a",
        "abbacd",
    ]
    for t in tests:
        print(shortest_palindrome(t))