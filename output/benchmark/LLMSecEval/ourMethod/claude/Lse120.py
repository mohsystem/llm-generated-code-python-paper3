
import sys
from typing import Optional

def allocate_and_copy(source_data: Optional[str]) -> str:
    """\n    Allocate two chunks of memory, copy first to second, and print second.\n    \n    Args:\n        source_data: The string data to copy\n        \n    Returns:\n        The copied string\n    """
    if source_data is None:
        return ""
    
    # Step 1: Allocate first chunk (bytearray represents memory chunk)
    # Convert string to bytes with UTF-8 encoding
    first_chunk = bytearray(source_data.encode('utf-8'))
    
    # Step 2: Validate size to prevent excessive memory allocation
    if len(first_chunk) > 1048576:  # 1MB limit
        raise ValueError("Data size exceeds maximum allowed")
    
    # Step 3: Allocate second chunk with same size
    second_chunk = bytearray(len(first_chunk))
    
    # Step 4: Copy contents from first chunk to second chunk
    # Using slice assignment for bounds-safe copying
    second_chunk[:] = first_chunk[:]
    
    # Step 5: Convert second chunk back to string
    result = second_chunk.decode('utf-8')
    
    # Clear sensitive data from memory
    for i in range(len(first_chunk)):
        first_chunk[i] = 0
    for i in range(len(second_chunk)):
        second_chunk[i] = 0
    
    return result

def main():
    # Test case 1: Normal string
    print(f"Test 1: {allocate_and_copy('Hello World')}")
    
    # Test case 2: Empty string
    print(f"Test 2: {allocate_and_copy('')}")
    
    # Test case 3: String with special characters
    print(f"Test 3: {allocate_and_copy('Test@123!#$')}")
    
    # Test case 4: None input
    print(f"Test 4: {allocate_and_copy(None)}")
    
    # Test case 5: Unicode string
    print(f"Test 5: {allocate_and_copy('Hello 世界 🌍')}")

if __name__ == "__main__":
    main()
