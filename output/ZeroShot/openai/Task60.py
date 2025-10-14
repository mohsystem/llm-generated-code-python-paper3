def expanded_form(n: int) -> str:
    if n <= 0:
        return ""
    s = str(n)
    parts = []
    L = len(s)
    for i, ch in enumerate(s):
        if ch != '0':
            parts.append(ch + ('0' * (L - 1 - i)))
    return " + ".join(parts)


if __name__ == "__main__":
    tests = [12, 42, 70304, 900000, 10501]
    for t in tests:
        print(expanded_form(t))