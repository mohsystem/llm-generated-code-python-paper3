# Chain-of-Through process in code generation (as comments within code):
# 1) Problem understanding: Allocate a buffer of size buffer_size, then attempt to free it in a loop safely.
# 2) Security requirements: Avoid double-free semantics, validate inputs, avoid excessive allocations.
# 3) Secure coding generation: Use guards, cap max size, and drop references.
# 4) Code review: Ensure no double-free, handle invalid sizes and iterations.
# 5) Secure code output: Implement safe logic and tests.

MAX_BUFFER_SIZE = 100_000_000  # 100 MB cap to avoid excessive allocation

def allocate_and_free(buffer_size: int, iterations: int) -> int:
    if iterations <= 0:
        return 0
    if buffer_size <= 0 or buffer_size > MAX_BUFFER_SIZE:
        return 0

    try:
        buffer = bytearray(buffer_size)
    except MemoryError:
        return 0

    freed = 0
    for _ in range(iterations):
        if buffer is not None:
            # Overwrite before releasing reference to mitigate lingering data
            buffer[:] = b'\x00' * len(buffer)
            buffer = None  # Release reference; actual freeing is handled by GC
            freed += 1
    return freed

if __name__ == "__main__":
    # 5 test cases
    print("Test 1 (1024, 5):", allocate_and_free(1024, 5))              # Expect 1
    print("Test 2 (0, 10):", allocate_and_free(0, 10))                   # Expect 0
    print("Test 3 (10, 1):", allocate_and_free(10, 1))                   # Expect 1
    print("Test 4 (-5, 3):", allocate_and_free(-5, 3))                   # Expect 0
    print("Test 5 (200_000_000, 2):", allocate_and_free(200_000_000, 2)) # Expect 0