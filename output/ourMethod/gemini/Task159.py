from typing import Optional, List

def create_buffer(size: int) -> bytearray:
    """
    Dynamically allocates and initializes a buffer.
    
    Args:
        size: The desired size of the buffer.
        
    Returns:
        A new bytearray of the specified size.
    """
    if size <= 0:
        raise ValueError("Buffer size must be positive.")
    # Populate buffer with some data
    return bytearray(i * 2 for i in range(size))

def read_from_buffer(buffer: bytearray, index: int) -> Optional[int]:
    """
    Safely reads a byte from the buffer at the given index.
    
    Args:
        buffer: The bytearray buffer to read from.
        index: The index of the byte to read.
        
    Returns:
        The byte value if the index is valid, otherwise None.
    """
    # Rules#1, Rules#4: Ensure that the index is within the buffer's boundaries.
    if 0 <= index < len(buffer):
        return buffer[index]
    else:
        return None

def main():
    """
    Main function to run test cases.
    """
    buffer_size = 20
    try:
        buffer = create_buffer(buffer_size)
        print(f"Testing reads from a buffer of size {buffer_size}:")

        test_indices = [0, 10, 19, -1, 20]

        for i, index in enumerate(test_indices):
            print(f"Test Case {i + 1}: Reading at index {index}... ", end="")
            
            result = read_from_buffer(buffer, index)
            
            if result is not None:
                print(f"Success! Value: {result}")
            else:
                print("Failed! Index is out of bounds.")
                
    except ValueError as e:
        print(f"Error creating buffer: {e}")

if __name__ == "__main__":
    main()