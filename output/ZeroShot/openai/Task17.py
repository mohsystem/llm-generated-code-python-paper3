def to_jaden_case(s: str) -> str:
    if not s:
        return ""
    res = []
    new_word = True
    for ch in s:
        if ch.isspace():
            res.append(ch)
            new_word = True
        else:
            if new_word and ch.isalpha():
                res.append(ch.upper())
            elif ch.isalpha():
                res.append(ch.lower())
            else:
                res.append(ch)
            new_word = False
    return "".join(res)


if __name__ == "__main__":
    tests = [
        "How can mirrors be real if our eyes aren't real",
        "",
        "most trees are blue",
        "HELLO WORLD",
        "multiple   spaces\tand tabs",
    ]
    for t in tests:
        print(to_jaden_case(t))