from __future__ import annotations

from typing import Optional


class MemoryResource:
    __slots__ = ("_data", "_closed")
    MAX_CAPACITY = 10_000_000

    def __init__(self, size: int) -> None:
        if not isinstance(size, int) or size <= 0 or size > self.MAX_CAPACITY:
            raise ValueError("Invalid size")
        self._data = bytearray(size)
        self._closed = False

    def capacity(self) -> int:
        return 0 if self._closed else len(self._data)

    def is_closed(self) -> bool:
        return self._closed

    def write(self, offset: int, data: bytes) -> int:
        if self._closed or not isinstance(offset, int) or data is None:
            return -1
        if offset < 0 or offset >= len(self._data):
            return -1
        writable = min(len(data), len(self._data) - offset)
        if writable <= 0:
            return -1
        # Bound-checked slice assignment
        self._data[offset : offset + writable] = data[:writable]
        return writable

    def read(self, offset: int, length: int) -> bytes:
        if self._closed or not isinstance(offset, int) or not isinstance(length, int):
            return b""
        if offset < 0 or length < 0 or offset >= len(self._data):
            return b""
        readable = min(length, len(self._data) - offset)
        if readable <= 0:
            return b""
        return bytes(self._data[offset : offset + readable])

    def close(self) -> None:
        if not self._closed:
            for i in range(len(self._data)):
                self._data[i] = 0
            self._data = bytearray(0)
            self._closed = True


def main() -> None:
    # Test 1: Basic allocation, write, read
    mr1 = MemoryResource(16)
    w1 = mr1.write(0, b"Hello")
    r1 = mr1.read(0, 5)
    print(f"T1: written={w1} read=\"{r1.decode('utf-8')}\" cap={mr1.capacity()}")

    # Test 2: Partial write near end
    mr2 = MemoryResource(16)
    w2 = mr2.write(13, b"World!")  # expect 3
    r2 = mr2.read(0, 16)
    print(f"T2: written={w2} read=\"{r2.decode('utf-8', errors='ignore')}\"")

    # Test 3: Write larger than capacity, ensure clamp
    mr3 = MemoryResource(8)
    w3 = mr3.write(0, b"123456789")  # expect 8
    r3 = mr3.read(0, 8)
    print(f"T3: written={w3} read=\"{r3.decode('utf-8')}\"")

    # Test 4: Use after close should fail
    mr4 = MemoryResource(10)
    mr4.close()
    w4 = mr4.write(0, b"X")  # expect -1
    r4 = mr4.read(0, 1)  # expect empty
    print(f"T4: written={w4} readLen={len(r4)} isClosed={mr4.is_closed()}")

    # Test 5: Invalid offset (negative)
    mr5 = MemoryResource(4)
    w5 = mr5.write(-1, b"AB")  # expect -1
    print(f"T5: written={w5} cap={mr5.capacity()}")


if __name__ == "__main__":
    main()