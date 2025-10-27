import sys

OFFSET = 1000

def add_offset(value: int) -> int:
    return value + OFFSET

def run_tests() -> None:
    tests = [0, 1, 999, -1000, 1234567890]
    for t in tests:
        try:
            result = add_offset(t)
            print(f"Test input: {t} -> {result}")
        except Exception as e:
            print(f"Test input: {t} -> Error: {e}", file=sys.stderr)

def main() -> None:
    run_tests()
    if len(sys.argv) > 1:
        try:
            arg = sys.argv[1].strip()
            value = int(arg, 10)
            result = add_offset(value)
            print(f"Command-line input: {value} -> {result}")
        except ValueError:
            print(f"Invalid number format: {sys.argv[1:]}", file=sys.stderr)

if __name__ == "__main__":
    main()