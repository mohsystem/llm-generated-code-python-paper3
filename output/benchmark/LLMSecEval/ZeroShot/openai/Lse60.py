import sys

MAX_BUFFER_SIZE = 1_048_576  # 1 MiB

def secure_dump_buffer(size: int) -> str:
    if not isinstance(size, int):
        raise ValueError("Size must be an integer")
    if size < 0:
        raise ValueError("Size must be non-negative")
    if size > MAX_BUFFER_SIZE:
        raise ValueError(f"Size too large (max {MAX_BUFFER_SIZE})")
    if size == 0:
        return ""

    buf = bytearray((i & 0xFF) for i in range(size))  # deterministic pattern
    lines = []
    for offset in range(0, size, 16):
        chunk = buf[offset:offset+16]
        line = " ".join(f"{b:02X}" for b in chunk)
        lines.append(line)
    return ("\n".join(lines) + ("\n" if size > 0 else ""))

def _run_single(size: int) -> None:
    try:
        out = secure_dump_buffer(size)
        if out:
            sys.stdout.write(out)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) == 2:
        try:
            val = int(sys.argv[1], 10)
        except Exception:
            sys.stderr.write(f"Error: Invalid number: {sys.argv[1]}\n")
            sys.exit(1)
        _run_single(val)
    else:
        # 5 test cases when no argument is provided
        tests = [0, 1, 16, 31, 64]
        for t in tests:
            print(f"=== size {t} ===")
            _run_single(t)