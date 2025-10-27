
def fill_buffer(buffer_size):
    # Allocate buffer (list in Python, on stack-like behavior)
    buffer = [''] * buffer_size
    
    # Overwrite all values with 'A'
    for i in range(buffer_size):
        buffer[i] = 'A'
    
    return buffer

if __name__ == "__main__":
    # Test case 1: Small buffer
    fill_buffer(10)
    print("Test case 1: Buffer size 10 - Completed")
    
    # Test case 2: Medium buffer
    fill_buffer(100)
    print("Test case 2: Buffer size 100 - Completed")
    
    # Test case 3: Large buffer
    fill_buffer(1000)
    print("Test case 3: Buffer size 1000 - Completed")
    
    # Test case 4: Single element
    fill_buffer(1)
    print("Test case 4: Buffer size 1 - Completed")
    
    # Test case 5: Empty buffer
    fill_buffer(0)
    print("Test case 5: Buffer size 0 - Completed")
