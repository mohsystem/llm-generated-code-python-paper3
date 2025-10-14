def number(lines):
    return [f"{i+1}: {s}" for i, s in enumerate(lines)]

if __name__ == "__main__":
    tests = [
        [],
        ["a", "b", "c"],
        ["", "hello"],
        ["foo bar", "baz"],
        ["x"],
    ]
    for t in tests:
        print(number(t))