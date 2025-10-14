from typing import List, Tuple

MAX_BUFFER_SIZE = 1_048_576

def allocate_buffer(size: int) -> bytearray:
    if not isinstance(size, int) or size < 0 or size > MAX_BUFFER_SIZE:
        raise ValueError("Invalid buffer size")
    return bytearray(size)

def fill_sequential(buffer: bytearray) -> None:
    if buffer is None:
        raise ValueError("Buffer is None")
    for i in range(len(buffer)):
        buffer[i] = i & 0xFF

def safe_read(buffer: bytearray, index: int) -> Tuple[bool, int]:
    if buffer is None:
        return (False, 0)
    if not isinstance(index, int) or index < 0 or index >= len(buffer):
        return (False, 0)
    return (True, buffer[index])

def main() -> None:
    buffer = allocate_buffer(10)
    fill_sequential(buffer)

    test_indices: List[int] = [-1, 0, 5, 9, 10]
    for idx in test_indices:
        ok, val = safe_read(buffer, idx)
        if ok:
            print(f"Index {idx} -> value: {val}")
        else:
            print(f"Index {idx} -> error: out of bounds")

    print(f"Buffer length: {len(buffer)}")
    print(f"Buffer content: {list(buffer)}")

if __name__ == "__main__":
    main()