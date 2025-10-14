# Chain-of-Through process in code generation applied with secure checks.
# Language: Python

from typing import Tuple, Optional

MAX_ALLOC = 10_000_000  # Prevent excessive allocation

def allocate_buffer(size: int) -> bytearray:
    if not isinstance(size, int):
        raise TypeError("size must be int")
    if size < 0 or size > MAX_ALLOC:
        raise ValueError("Invalid buffer size")
    buf = bytearray(size)
    for i in range(size):
        buf[i] = i & 0xFF
    return buf

def read_from_buffer(buffer: Optional[bytearray], index: int) -> Tuple[bool, int]:
    if buffer is None:
        return (False, 0)
    if not isinstance(index, int):
        return (False, 0)
    if index < 0 or index >= len(buffer):
        return (False, 0)
    return (True, buffer[index])

def main():
    buffer = allocate_buffer(10)
    test_indices = [0, 5, 9, -1, 10]
    for idx in test_indices:
        ok, val = read_from_buffer(buffer, idx)
        if ok:
            print(f"Index {idx} -> {val}")
        else:
            print(f"Index {idx} -> invalid index")

if __name__ == "__main__":
    main()