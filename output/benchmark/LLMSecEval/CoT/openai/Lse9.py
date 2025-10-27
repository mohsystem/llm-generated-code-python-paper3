import sys

def get_arg_at_index(argv, index):
    if argv is None:
        return None
    if index < 0 or index >= len(argv):
        return None
    return argv[index]

def _run_tests():
    test_argv = ["prog", "1", "alpha", "beta", "gamma"]
    test_indices = [1, 2, 4, 0, 10]
    for idx in test_indices:
        res = get_arg_at_index(test_argv, idx)
        if res is not None:
            print(res)
        else:
            print("ERROR")

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        _run_tests()
        sys.exit(0)
    try:
        idx = int(sys.argv[1])
        if idx < 0:
            print("Error: index must be non-negative", file=sys.stderr)
            sys.exit(1)
    except ValueError:
        print("Error: invalid index", file=sys.stderr)
        sys.exit(1)
    result = get_arg_at_index(sys.argv, idx)
    if result is None:
        print("Error: index out of range", file=sys.stderr)
        sys.exit(1)
    print(result)