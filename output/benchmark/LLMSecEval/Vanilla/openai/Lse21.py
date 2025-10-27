import sys

def add1000(x: int) -> int:
    return x + 1000

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        try:
            x = int(sys.argv[1])
            result = add1000(x)
            print(result)
            sys.exit(0)
        except ValueError:
            pass
    tests = [-1000, -1, 0, 1, 12345]
    for t in tests:
        print(add1000(t))
    sys.exit(0)