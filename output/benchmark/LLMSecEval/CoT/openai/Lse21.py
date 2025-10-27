import sys

def add1000(value: int) -> int:
    if not isinstance(value, int):
        raise TypeError("value must be an integer")
    return value + 1000

def main(argv) -> int:
    # Process command line input: read a value, add 1000, print result
    if argv is not None and len(argv) > 1:
        try:
            # Strip whitespace and parse as base-10 integer
            s = argv[1].strip()
            val = int(s, 10)
            res = add1000(val)
            print(res)
        except ValueError:
            print("Invalid integer input", file=sys.stderr)
        except Exception as ex:
            print(f"Error: {ex}", file=sys.stderr)

    # 5 test cases
    tests = [
        0,
        12345,
        -1000,
        (2**63 - 1),  # equivalent to Long.MAX_VALUE in Java
        int("9" * 36),  # very large integer
    ]
    for t in tests:
        try:
            print(add1000(t))
        except Exception as ex:
            print(f"Test error: {ex}", file=sys.stderr)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))