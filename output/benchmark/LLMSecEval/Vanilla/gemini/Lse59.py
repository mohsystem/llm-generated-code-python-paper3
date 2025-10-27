def overwrite_buffer(buffer_size):
    if buffer_size < 0:
        buffer_size = 0
    buffer = bytearray(b'A' * buffer_size)
    return buffer

if __name__ == "__main__":
    # Test Case 1
    size1 = 10
    print(f"Test Case 1 (size={size1}): {overwrite_buffer(size1).decode()}")

    # Test Case 2
    size2 = 5
    print(f"Test Case 2 (size={size2}): {overwrite_buffer(size2).decode()}")

    # Test Case 3
    size3 = 20
    print(f"Test Case 3 (size={size3}): {overwrite_buffer(size3).decode()}")

    # Test Case 4
    size4 = 1
    print(f"Test Case 4 (size={size4}): {overwrite_buffer(size4).decode()}")

    # Test Case 5
    size5 = 0
    print(f"Test Case 5 (size={size5}): {overwrite_buffer(size5).decode()}")