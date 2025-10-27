OFFSET = 1000

def add_offset(value: int) -> int:
    return int(value) + OFFSET

if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        s = (sys.argv[1] or "").strip()
        if s == "":
            print("Error: empty input", file=sys.stderr)
            sys.exit(1)
        try:
            v = int(s, 10)
        except ValueError:
            print("Error: invalid integer input", file=sys.stderr)
            sys.exit(1)
        print(add_offset(v))
    else:
        tests = [0, 1, -1, (2**63 - 1) - 1000, (-2**63) + 1000]
        for t in tests:
            print(f"add_offset({t}) = {add_offset(t)}")