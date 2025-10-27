import sys

MAX_SIZE = 1_048_576  # 1 MiB cap to prevent excessive memory use

def allocate_and_dump_buffer(size: int) -> str:
    if not isinstance(size, int):
        raise ValueError("Invalid size")
    if size < 0 or size > MAX_SIZE:
        raise ValueError("Invalid size")
    if size == 0:
        return ""
    buf = bytearray(size)  # zero-initialized
    # Build hex representation with spaces, e.g., "00 00 ..."
    return " ".join(f"{b:02x}" for b in buf)

def _run_single(size: int) -> None:
    try:
        out = allocate_and_dump_buffer(size)
        print(out)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def main() -> None:
    if len(sys.argv) >= 2:
        try:
            val = int(sys.argv[1], 10)
        except Exception:
            print("Error: invalid integer size", file=sys.stderr)
            sys.exit(1)
        _run_single(val)
    else:
        tests = [0, 1, 8, 16, 64]
        for t in tests:
            _run_single(t)

if __name__ == "__main__":
    main()