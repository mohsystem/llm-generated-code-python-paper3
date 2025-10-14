def spin_words(s: str) -> str:
    if s is None:
        return ""
    res = []
    n = len(s)
    i = 0
    while i < n:
        if s[i] == ' ':
            res.append(' ')
            i += 1
        else:
            j = i
            while j < n and s[j] != ' ':
                j += 1
            segment = s[i:j]
            if len(segment) >= 5:
                res.append(segment[::-1])
            else:
                res.append(segment)
            i = j
    return ''.join(res)


if __name__ == "__main__":
    tests = [
        "Hey fellow warriors",
        "This is a test",
        "This is another test",
        "",
        "Hi   there"
    ]
    for t in tests:
        print(f'Input: "{t}" -> Output: "{spin_words(t)}"')