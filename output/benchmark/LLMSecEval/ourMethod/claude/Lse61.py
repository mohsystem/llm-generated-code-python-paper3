
import sys

def allocate_and_free_buffer(buffer_size: int, iterations: int) -> None:
    """\n    Demonstrates proper memory management pattern.\n    Allocates and deallocates buffer correctly - no double-free.\n    \n    Args:\n        buffer_size: Size of buffer to allocate\n        iterations: Number of allocation cycles\n    """
    # Validate input to prevent negative or excessive allocations
    if buffer_size <= 0 or buffer_size > 100 * 1024 * 1024:  # Max 100MB
        raise ValueError("Invalid buffer size")
    if iterations <= 0 or iterations > 1000:
        raise ValueError("Invalid iteration count")
    
    # Correct pattern: allocate and free within each iteration
    # This prevents double-free vulnerability
    for i in range(iterations):
        # Allocate buffer for this iteration
        buffer = bytearray(buffer_size)
        
        # Use buffer (example: initialize to demonstrate allocation worked)
        if len(buffer) > 0:
            buffer[0] = i % 256
        
        # In Python, explicit free not needed - GC handles it
        # Setting to None helps GC in tight loops
        buffer = None

def main():
    # Test case 1: Small buffer, few iterations
    allocate_and_free_buffer(1024, 5)
    print("Test 1 passed: 1KB buffer, 5 iterations")
    
    # Test case 2: Medium buffer, moderate iterations
    allocate_and_free_buffer(8192, 10)
    print("Test 2 passed: 8KB buffer, 10 iterations")
    
    # Test case 3: Larger buffer, single iteration
    allocate_and_free_buffer(65536, 1)
    print("Test 3 passed: 64KB buffer, 1 iteration")
    
    # Test case 4: Small buffer, many iterations
    allocate_and_free_buffer(512, 100)
    print("Test 4 passed: 512B buffer, 100 iterations")
    
    # Test case 5: Edge case - minimum valid size
    allocate_and_free_buffer(1, 3)
    print("Test 5 passed: 1B buffer, 3 iterations")

if __name__ == "__main__":
    main()
