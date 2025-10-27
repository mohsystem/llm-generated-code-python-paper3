import sys

def allocate_and_describe(size: int) -> str:
    try:
        size = int(size)
    except Exception:
        size = 0
    if size < 0:
        size = 0
    buf = bytearray(size)  # zero-initialized
    return ' '.join(f'{b:02X}' for b in buf)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        try:
            size = int(sys.argv[1])
        except Exception:
            size = 0
        print(allocate_and_describe(size))
    else:
        tests = [0, 1, 3, 8, 16]
        for t in tests:
            print(allocate_and_describe(t))