def expanded_form(num):
    s = str(num)
    parts = []
    for i, ch in enumerate(s):
        if ch != '0':
            place = 10 ** (len(s) - i - 1)
            parts.append(str(int(ch) * place))
    return " + ".join(parts)

if __name__ == "__main__":
    tests = [12, 42, 70304, 9000000, 105]
    for t in tests:
        print(f"{t} -> {expanded_form(t)}")