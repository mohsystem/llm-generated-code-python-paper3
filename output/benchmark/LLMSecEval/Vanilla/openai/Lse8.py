def value_at_index_from_arg1(argv):
    if argv is None or len(argv) < 2:
        return None
    try:
        idx = int(argv[1])
    except ValueError:
        return None
    if 0 <= idx < len(argv):
        return argv[idx]
    return None

if __name__ == "__main__":
    tests = [
        ["prog", "2", "a", "b", "c"],
        ["prog", "0", "X"],
        ["prog", "4", "w", "x", "y", "z"],
        ["prog", "1", "hello"],
        ["prog", "3", "p", "q", "r", "s"]
    ]
    for t in tests:
        print(value_at_index_from_arg1(t))