
import sys

def fill_buffer_with_a(buffer_size):
    """\n    Allocates a buffer and fills it with 'A'\n    \n    Parameters:\n        buffer_size: the size of the buffer to allocate\n    \n    Returns:\n        bytearray: the filled buffer\n    """
    # Validate input: buffer size must be positive and within reasonable limits
    # to prevent excessive memory usage (max 10MB)
    if not isinstance(buffer_size, int):
        raise TypeError("Buffer size must be an integer")
    
    if buffer_size <= 0 or buffer_size > 10 * 1024 * 1024:
        raise ValueError("Buffer size must be positive and not exceed 10MB")
    
    # Allocate buffer on the stack (as a local bytearray variable)
    # In Python, local variables are stack-allocated
    buffer = bytearray(buffer_size)
    
    # Fill buffer with 'A' (ASCII 65) - using slice assignment for bounds-safe operation
    # This prevents any potential buffer overflow
    for i in range(buffer_size):
        buffer[i] = ord('A')
    
    return buffer

def main():
    # Test case 1: Small buffer
    try:
        result1 = fill_buffer_with_a(10)
        print(f"Test 1 - Size 10: {result1.decode('ascii')}")
    except Exception as e:
        print(f"Test 1 failed: {e}")
    
    # Test case 2: Medium buffer
    try:
        result2 = fill_buffer_with_a(100)
        print(f"Test 2 - Size 100: Length = {len(result2)}, First 10 chars: {result2[:10].decode('ascii')}")
    except Exception as e:
        print(f"Test 2 failed: {e}")
    
    # Test case 3: Large buffer
    try:
        result3 = fill_buffer_with_a(1000)
        print(f"Test 3 - Size 1000: Length = {len(result3)}")
    except Exception as e:
        print(f"Test 3 failed: {e}")
    
    # Test case 4: Edge case - size 1
    try:
        result4 = fill_buffer_with_a(1)
        print(f"Test 4 - Size 1: {result4.decode('ascii')}")
    except Exception as e:
        print(f"Test 4 failed: {e}")
    
    # Test case 5: Invalid input - negative size
    try:
        result5 = fill_buffer_with_a(-1)
        print("Test 5 - Negative size should fail")
    except Exception as e:
        print(f"Test 5 - Correctly rejected negative size: {e}")

if __name__ == "__main__":
    main()
