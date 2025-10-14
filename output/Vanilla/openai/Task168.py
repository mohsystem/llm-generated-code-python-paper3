def tweakLetters(s, arr):
    s = s.lower()
    res = []
    for i, ch in enumerate(s):
        if i < len(arr) and 'a' <= ch <= 'z':
            pos = ord(ch) - ord('a')
            pos = (pos + arr[i]) % 26
            res.append(chr(ord('a') + pos))
        else:
            res.append(ch)
    return ''.join(res)

if __name__ == "__main__":
    tests = [
        ("apple", [0, 1, -1, 0, -1]),
        ("many", [0, 0, 0, -1]),
        ("rhino", [1, 1, 1, 1, 1]),
        ("xyz", [1, 1, 1]),
        ("zoo", [1, 0, 0]),
    ]
    for s, arr in tests:
        print(tweakLetters(s, arr))