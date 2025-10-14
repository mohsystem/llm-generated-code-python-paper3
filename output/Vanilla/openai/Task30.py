def longest(s1, s2):
    present = [False] * 26
    for c in s1:
        if 'a' <= c <= 'z':
            present[ord(c) - ord('a')] = True
    for c in s2:
        if 'a' <= c <= 'z':
            present[ord(c) - ord('a')] = True
    return ''.join(chr(i + ord('a')) for i in range(26) if present[i])

if __name__ == "__main__":
    tests = [
        ("xyaabbbccccdefww", "xxxxyyyyabklmopq"),
        ("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("", ""),
        ("aaabbb", "bbbccc"),
        ("hello", "world"),
    ]
    for a, b in tests:
        print(longest(a, b))