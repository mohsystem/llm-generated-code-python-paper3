import gc

MAX_SIZE = 16 * 1024 * 1024

def allocate_and_use(size: int) -> int:
    """
    Dynamically allocates a bytearray, uses it, then securely clears and dereferences it.
    Returns checksum on success, -1 on error.
    """
    if not isinstance(size, int) or size <= 0 or size > MAX_SIZE:
        return -1
    try:
        buf = bytearray(size)
        for i in range(size):
            buf[i] = i & 0xFF
        checksum = 0
        # Using local variable to avoid Python's sum on generator creating extra objects
        for b in buf:
            checksum += b
        # Securely overwrite buffer before release
        for i in range(size):
            buf[i] = 0
        del buf
        # Hint GC (not required, but explicit for demonstration)
        gc.collect()
        return checksum
    except MemoryError:
        return -1

if __name__ == "__main__":
    tests = [1, 64, 1024, 4096, 1_000_000]
    for t in tests:
        res = allocate_and_use(t)
        print(f"size={t} checksum={res}")