
from typing import Optional


class BufferReader:
    MIN_INDEX: int = 0
    MAX_BUFFER_SIZE: int = 1000000
    
    def __init__(self, size: int) -> None:
        if not isinstance(size, int):
            raise TypeError("Buffer size must be an integer")
        if size <= 0 or size > self.MAX_BUFFER_SIZE:
            raise ValueError(f"Buffer size must be between 1 and {self.MAX_BUFFER_SIZE}")
        
        self._size: int = size
        self._buffer: bytearray = bytearray(size)
        self._initialize_buffer()
    
    def _initialize_buffer(self) -> None:
        data: bytes = b"Hello, this is sample data in the buffer for testing purposes."
        copy_length: int = min(len(data), len(self._buffer))
        self._buffer[:copy_length] = data[:copy_length]
    
    def read_at_index(self, index: int) -> int:
        if not isinstance(index, int):
            raise TypeError("Index must be an integer")
        
        if index < self.MIN_INDEX or index >= self._size:
            raise IndexError(
                f"Index {index} is out of bounds. Valid range: [{self.MIN_INDEX}, {self._size})"
            )
        
        return self._buffer[index]
    
    def get_size(self) -> int:
        return self._size


def test_read_at_index(buffer_size: int, index: int) -> None:
    try:
        reader = BufferReader(buffer_size)
        value = reader.read_at_index(index)
        char_repr = chr(value) if 32 <= value < 127 else '?'
        print(f"Successfully read byte at index {index}: {value} (char: '{char_repr}')")
    except (IndexError, ValueError, TypeError) as e:
        print(f"Error reading at index {index}: {e}")


def main() -> None:
    BUFFER_SIZE: int = 100
    
    print("=== Test Case 1: Valid index at start ===")
    test_read_at_index(BUFFER_SIZE, 0)
    
    print("\\n=== Test Case 2: Valid index in middle ===")
    test_read_at_index(BUFFER_SIZE, 10)
    
    print("\\n=== Test Case 3: Valid index at end ===")
    test_read_at_index(BUFFER_SIZE, BUFFER_SIZE - 1)
    
    print("\\n=== Test Case 4: Invalid negative index ===")
    test_read_at_index(BUFFER_SIZE, -1)
    
    print("\\n=== Test Case 5: Invalid index beyond buffer ===")
    test_read_at_index(BUFFER_SIZE, BUFFER_SIZE)


if __name__ == "__main__":
    main()
