import sys

def add_thousand(x: int) -> int:
    if not isinstance(x, int):
        raise TypeError("Input must be an integer")
    return x + 1000

def main(argv) -> int:
    try:
        if len(argv) > 1:
            s = argv[1].strip()
            val = int(s)
            print(add_thousand(val))
        else:
            tests = [-1000, -1, 0, 1, 9223372036854774800]
            for t in tests:
                print(add_thousand(t))
    except ValueError:
        print("Invalid integer input.", file=sys.stderr)
    except Exception:
        print("An unexpected error occurred.", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))