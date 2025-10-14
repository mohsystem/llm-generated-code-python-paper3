def expanded_form(n: int) -> str:
    if n <= 0:
        return "0"
    s = str(n)
    parts = []
    L = len(s)
    for i, ch in enumerate(s):
        if ch != '0':
            parts.append(ch + ('0' * (L - i - 1)))
    return ' + '.join(parts)

if __name__ == "__main__":
    tests = [12, 42, 70304, 9000000, 102030]
    for t in tests:
        print(f"{t} -> {expanded_form(t)}")