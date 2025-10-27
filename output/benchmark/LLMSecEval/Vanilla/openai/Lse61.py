def allocate_and_free_in_loop(buffer_size: int, loops: int) -> int:
    """
    Allocates a buffer of size buffer_size, then frees it in a loop.
    Returns the number of times the buffer was actually freed (non-None to None transition).
    """
    buffer = bytearray(buffer_size)
    frees = 0
    for _ in range(loops):
        if buffer is not None:
            buffer = None  # Release reference to allow GC
            frees += 1
        # Subsequent iterations do nothing since buffer is already None
    return frees


if __name__ == "__main__":
    tests = [
        (0, 1),
        (1, 3),
        (16, 5),
        (1024, 2),
        (65536, 10),
    ]
    for i, (size, lp) in enumerate(tests, 1):
        res = allocate_and_free_in_loop(size, lp)
        print(f"Test {i}: size={size}, loops={lp}, frees={res}")