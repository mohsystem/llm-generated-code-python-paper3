def run(args):
    out = []
    if args is None or len(args) != 1:
        out.append("Error: expected exactly one argument.")
        return out
    input_str = args[0]
    out.append(input_str)
    trimmed = input_str.rstrip()
    out.append(trimmed)
    return out

if __name__ == "__main__":
    tests = [
        [],
        ["hello"],
        ["hello   "],
        ["world\t \t"],
        ["a", "b"],
    ]
    for t in tests:
        res = run(t)
        for line in res:
            print(line)