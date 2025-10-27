
def allocate_and_free_buffer(buffer_size):
    if buffer_size <= 0:
        print("Invalid buffer size")
        return
    
    # Allocate buffer
    buffer = bytearray(buffer_size)
    print(f"Buffer of size {buffer_size} allocated")
    
    # Use the buffer (example)
    for i in range(min(buffer_size, 10)):
        buffer[i] = i
    
    # In Python, memory is managed automatically
    # Deleting the reference allows garbage collection
    del buffer
    print("Buffer freed (eligible for garbage collection)")
    
    # Note: Freeing in a loop would cause issues in manual memory management languages
    # Python handles this through garbage collection

if __name__ == "__main__":
    print("Test Case 1: Small buffer")
    allocate_and_free_buffer(10)
    
    print("\\nTest Case 2: Medium buffer")
    allocate_and_free_buffer(100)
    
    print("\\nTest Case 3: Large buffer")
    allocate_and_free_buffer(1000)
    
    print("\\nTest Case 4: Invalid buffer (zero)")
    allocate_and_free_buffer(0)
    
    print("\\nTest Case 5: Invalid buffer (negative)")
    allocate_and_free_buffer(-10)
