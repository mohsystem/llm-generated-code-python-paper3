from typing import Optional

MAX_BUFFER_SIZE = 16 * 1024 * 1024  # 16 MiB

def free_buffer_in_loop(buffer_size: int, loops: int) -> int:
    if not isinstance(buffer_size, int) or not isinstance(loops, int):
        return -1
    if buffer_size < 0 or buffer_size > MAX_BUFFER_SIZE or loops < 0:
        return -1

    # Allocate
    try:
        buf: Optional[bytearray] = bytearray(buffer_size)
    except MemoryError:
        return -1

    frees = 0
    # Free in a loop (guard against double-free)
    for _ in range(loops):
        if buf is not None:
            # Securely wipe
            if buffer_size:
                mv = memoryview(buf)
                mv[:] = b"\x00" * len(mv)
                mv.release()
            buf = None
            frees += 1

    # Ensure cleanup if not freed in the loop
    if buf is not None:
        if buffer_size:
            mv = memoryview(buf)
            mv[:] = b"\x00" * len(mv)
            mv.release()
        buf = None
        frees += 1

    return frees

if __name__ == "__main__":
    # 5 test cases
    print(free_buffer_in_loop(1024, 3))           # Expect 1
    print(free_buffer_in_loop(2048, 1))           # Expect 1
    print(free_buffer_in_loop(4096, 0))           # Expect 1 (cleanup)
    print(free_buffer_in_loop(8192, 5))           # Expect 1
    print(free_buffer_in_loop(16 * 1024 * 1024, 2))  # Expect 1