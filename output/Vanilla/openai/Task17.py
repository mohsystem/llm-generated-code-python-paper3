def to_jaden_case(s):
    if s is None:
        return None
    if s == "":
        return ""
    res = []
    new_word = True
    for ch in s:
        if new_word and ch.isalpha():
            res.append(ch.upper())
        elif ch.isalpha():
            res.append(ch.lower())
        else:
            res.append(ch)
        new_word = ch.isspace() or ch == '-'
    return ''.join(res)

if __name__ == "__main__":
    tests = [
        "How can mirrors be real if our eyes aren't real",
        "",
        "not jaden-cased string",
        "this IS a tESt",
        None
    ]
    for t in tests:
        print("Input: ", t)
        print("Output:", to_jaden_case(t))
        print("---")