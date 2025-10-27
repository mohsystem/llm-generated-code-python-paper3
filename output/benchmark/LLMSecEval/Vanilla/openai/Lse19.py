import sys

def add1000(x):
    return x + 1000

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            val = int(sys.argv[1])
            print(add1000(val))
        except ValueError:
            print(f"Invalid number: {sys.argv[1]}", file=sys.stderr)
    tests = [-1000, 0, 42, 999_999_999_999, 9_223_372_036_854_774_807]
    for t in tests:
        print(add1000(t))