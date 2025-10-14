
from typing import Optional
import sys


MIN_SIZE: int = 1
MAX_SIZE: int = 1_000_000


def allocate_memory(size: int) -> Optional[bytearray]:
    """\n    Dynamically allocates a bytearray of the specified size.\n    \n    Args:\n        size: The size of the array to allocate\n        \n    Returns:\n        A newly allocated bytearray, or None if invalid size\n    """
    if not isinstance(size, int):
        print("Error: Size must be an integer", file=sys.stderr)
        return None
        
    if size < MIN_SIZE or size > MAX_SIZE:
        print(f"Error: Size must be between {MIN_SIZE} and {MAX_SIZE}", file=sys.stderr)
        return None
    
    try:
        memory: bytearray = bytearray(size)
        return memory
    except MemoryError:
        print(f"Error: Failed to allocate memory of size {size}", file=sys.stderr)
        return None


def deallocate_memory(memory: Optional[bytearray]) -> None:
    """\n    Deallocates memory by zeroing it and clearing the reference.\n    \n    Args:\n        memory: The memory to deallocate\n    """
    if memory is not None:
        for i in range(len(memory)):
            memory[i] = 0
        memory.clear()


def write_to_memory(memory: Optional[bytearray], data: bytes, offset: int) -> bool:
    """\n    Writes data to allocated memory with bounds checking.\n    \n    Args:\n        memory: The allocated memory\n        data: The data to write\n        offset: The offset in memory to start writing\n        \n    Returns:\n        True if successful, False otherwise\n    """
    if memory is None or data is None:
        print("Error: Memory or data is None", file=sys.stderr)
        return False
    
    if not isinstance(offset, int) or offset < 0 or offset > len(memory):
        print("Error: Invalid offset", file=sys.stderr)
        return False
    
    if len(data) > len(memory) - offset:
        print("Error: Data too large for memory buffer", file=sys.stderr)
        return False
    
    memory[offset:offset + len(data)] = data
    return True


def read_from_memory(memory: Optional[bytearray], offset: int, length: int) -> Optional[bytes]:
    """\n    Reads data from allocated memory with bounds checking.\n    \n    Args:\n        memory: The allocated memory\n        offset: The offset to start reading\n        length: The number of bytes to read\n        \n    Returns:\n        The read data, or None if error\n    """
    if memory is None:
        print("Error: Memory is None", file=sys.stderr)
        return None
    
    if not isinstance(offset, int) or not isinstance(length, int):
        print("Error: Offset and length must be integers", file=sys.stderr)
        return None
    
    if offset < 0 or offset >= len(memory):
        print("Error: Invalid offset", file=sys.stderr)
        return None
    
    if length < 0 or length > len(memory) - offset:
        print("Error: Invalid length", file=sys.stderr)
        return None
    
    return bytes(memory[offset:offset + length])


def main() -> None:
    print("Test Case 1: Basic allocation and deallocation")
    mem1: Optional[bytearray] = allocate_memory(100)
    if mem1 is not None:
        print("Allocated 100 bytes successfully")
        deallocate_memory(mem1)
        print("Deallocated successfully\\n")
    
    print("Test Case 2: Write and read operations")
    mem2: Optional[bytearray] = allocate_memory(50)
    if mem2 is not None:
        test_data: str = "Hello, World!"
        data_bytes: bytes = test_data.encode('utf-8')
        
        if write_to_memory(mem2, data_bytes, 0):
            print("Written data to memory")
            read_data: Optional[bytes] = read_from_memory(mem2, 0, len(data_bytes))
            if read_data is not None:
                read_string: str = read_data.decode('utf-8')
                print(f"Read data: {read_string}")
        deallocate_memory(mem2)
        print()
    
    print("Test Case 3: Invalid size allocation")
    mem3: Optional[bytearray] = allocate_memory(-10)
    if mem3 is None:
        print("Correctly rejected negative size")
    mem3 = allocate_memory(2_000_000)
    if mem3 is None:
        print("Correctly rejected oversized allocation\\n")
    
    print("Test Case 4: Buffer overflow prevention")
    mem4: Optional[bytearray] = allocate_memory(10)
    if mem4 is not None:
        large_data: bytes = bytes(20)
        if not write_to_memory(mem4, large_data, 0):
            print("Correctly prevented buffer overflow")
        deallocate_memory(mem4)
        print()
    
    print("Test Case 5: Out of bounds read")
    mem5: Optional[bytearray] = allocate_memory(20)
    if mem5 is not None:
        result: Optional[bytes] = read_from_memory(mem5, 15, 10)
        if result is None:
            print("Correctly prevented out of bounds read")
        deallocate_memory(mem5)


if __name__ == "__main__":
    main()
