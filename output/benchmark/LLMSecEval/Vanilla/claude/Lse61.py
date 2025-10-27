
import gc

def allocate_and_free_buffer(buffer_size, iterations):
    for i in range(iterations):
        buffer = bytearray(buffer_size)
        # In Python, explicit deallocation is not needed
        # The garbage collector will handle memory cleanup
        del buffer
        gc.collect()  # Force garbage collection

def main():
    # Test case 1: Small buffer, few iterations
    print("Test 1: Buffer size 1024, 5 iterations")
    allocate_and_free_buffer(1024, 5)
    
    # Test case 2: Medium buffer, moderate iterations
    print("Test 2: Buffer size 4096, 10 iterations")
    allocate_and_free_buffer(4096, 10)
    
    # Test case 3: Large buffer, few iterations
    print("Test 3: Buffer size 1048576, 3 iterations")
    allocate_and_free_buffer(1048576, 3)
    
    # Test case 4: Small buffer, many iterations
    print("Test 4: Buffer size 512, 20 iterations")
    allocate_and_free_buffer(512, 20)
    
    # Test case 5: Very small buffer, moderate iterations
    print("Test 5: Buffer size 128, 15 iterations")
    allocate_and_free_buffer(128, 15)
    
    print("All tests completed")

if __name__ == "__main__":
    main()
