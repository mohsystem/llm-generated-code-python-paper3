
MAX_BUFFER_SIZE = 1024  # Limit to prevent excessive memory usage

def allocate_and_fill_buffer(buffer_size):
    # Validate input
    if not isinstance(buffer_size, int):
        raise TypeError("Buffer size must be an integer")
    if buffer_size <= 0:
        raise ValueError("Buffer size must be positive")
    if buffer_size > MAX_BUFFER_SIZE:
        raise ValueError("Buffer size exceeds maximum allowed size")
    
    # Allocate buffer (list acts as stack-allocated buffer)
    buffer = ['A'] * buffer_size
    
    return ''.join(buffer)

if __name__ == "__main__":
    # Test case 1: Normal size
    print(f"Test 1 (size 10): {allocate_and_fill_buffer(10)}")
    
    # Test case 2: Small size
    print(f"Test 2 (size 1): {allocate_and_fill_buffer(1)}")
    
    # Test case 3: Medium size
    result = allocate_and_fill_buffer(50)
    print(f"Test 3 (size 50): {result[:20]}...")
    
    # Test case 4: Larger size
    result = allocate_and_fill_buffer(500)
    print(f"Test 4 (size 500): Length = {len(result)}")
    
    # Test case 5: Edge case - invalid size
    try:
        allocate_and_fill_buffer(0)
    except ValueError as e:
        print(f"Test 5: Caught expected exception - {e}")
