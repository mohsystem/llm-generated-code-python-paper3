def longest(s1, s2):
    flags = [False] * 26
    for s in (s1, s2):
        if s is None:
            continue
        for ch in s:
            oc = ord(ch)
            if 97 <= oc <= 122:
                flags[oc - 97] = True
    return ''.join(chr(97 + i) for i, v in enumerate(flags) if v)


if __name__ == "__main__":
    tests = [
        ("xyaabbbccccdefww", "xxxxyyyyabklmopq"),
        ("abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
        ("", ""),
        ("abc123", "def!ghi"),
        ("thequickbrownfox", "jumpsoverthelazydog"),
    ]
    for a, b in tests:
        print(longest(a, b))