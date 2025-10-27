
def allocate_and_fill_buffer(buffer_size):
    buffer = ['A'] * buffer_size
    return buffer

if __name__ == "__main__":
    # Test case 1
    allocate_and_fill_buffer(10)
    print("Test case 1: Buffer size 10 - Completed")
    
    # Test case 2
    allocate_and_fill_buffer(50)
    print("Test case 2: Buffer size 50 - Completed")
    
    # Test case 3
    allocate_and_fill_buffer(100)
    print("Test case 3: Buffer size 100 - Completed")
    
    # Test case 4
    allocate_and_fill_buffer(1)
    print("Test case 4: Buffer size 1 - Completed")
    
    # Test case 5
    allocate_and_fill_buffer(500)
    print("Test case 5: Buffer size 500 - Completed")
