from typing import Optional

def allocate_and_free_loop(buffer_size: int, iterations: int) -> int:
    if buffer_size < 0 or iterations < 0:
        return -1  # invalid input

    class SafeBuffer:
        def __init__(self, n: int):
            # Allocate and initialize buffer
            self._data: Optional[bytearray] = bytearray(n)
            for i in range(len(self._data)):
                self._data[i] = 0
            self._freed: bool = False

        def free(self) -> int:
            if not self._freed:
                self._data = None
                self._freed = True
                return 1
            return 0

        @property
        def freed(self) -> bool:
            return self._freed

    # Handle zero-size safely (still simulate idempotent free calls)
    if buffer_size == 0:
        freed = False
        frees = 0
        for _ in range(iterations):
            if not freed:
                freed = True
                frees += 1
        if not freed:
            frees += 1
        return frees

    buf = SafeBuffer(buffer_size)
    frees = 0
    for _ in range(iterations):
        frees += buf.free()
    if not buf.freed:
        frees += buf.free()
    return frees

if __name__ == "__main__":
    # 5 test cases
    print(allocate_and_free_loop(16, 5))    # Expect 1
    print(allocate_and_free_loop(0, 5))     # Expect 1 (simulated single free)
    print(allocate_and_free_loop(1024, 1))  # Expect 1
    print(allocate_and_free_loop(8, 0))     # Expect 1 (cleanup)
    print(allocate_and_free_loop(-1, 3))    # Expect -1 (invalid)