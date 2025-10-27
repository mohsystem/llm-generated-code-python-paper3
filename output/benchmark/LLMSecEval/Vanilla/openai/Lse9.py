import sys

def get_arg_at(argv, index):
    return argv[index] if 0 <= index < len(argv) else None

if __name__ == "__main__":
    # 5 test cases
    tests = [
        (["prog", "alpha", "beta", "gamma"], 1),
        (["prog"], 0),
        (["app", "x"], 5),
        (["p", "10", "20", "30"], 3),
        (["name", "first", "second"], 2),
    ]
    for arr, idx in tests:
        res = get_arg_at(arr, idx)
        print(res if res is not None else "Index out of range")

    # Handle actual command line
    if len(sys.argv) >= 2:
        try:
            idx = int(sys.argv[1])
            res = get_arg_at(sys.argv, idx)
            print(res if res is not None else "Index out of range")
        except ValueError:
            print("Invalid index")