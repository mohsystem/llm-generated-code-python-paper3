import sys

MAX_SIZE = 1_048_576  # 1 MiB upper bound for safety

def allocate_and_get_hex(size: int) -> str:
    if not isinstance(size, int):
        raise TypeError("Size must be an integer.")
    if size < 0:
        raise ValueError("Size must be non-negative.")
    if size > MAX_SIZE:
        raise ValueError("Requested size exceeds safe limit.")
    buf = bytes(size)  # zero-initialized
    return buf.hex()

def _parse_size_arg(arg: str):
    try:
        val = int(arg, 10)
        if val < 0:
            return None
        return val
    except Exception:
        return None

def main():
    if len(sys.argv) == 2:
        sz = _parse_size_arg(sys.argv[1])
        if sz is None:
            print("Invalid size argument.", file=sys.stderr)
            sys.exit(1)
        try:
            print(allocate_and_get_hex(sz))
        except Exception as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        return
    # 5 test cases if no argument is provided
    tests = [0, 1, 8, 16, 32]
    for t in tests:
        try:
            print(allocate_and_get_hex(t))
        except Exception as e:
            print(f"Test case failed for size {t}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()