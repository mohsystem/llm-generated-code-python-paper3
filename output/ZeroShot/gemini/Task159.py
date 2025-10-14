import typing

def secure_read(buffer: bytearray, index: int) -> typing.Optional[int]:
    """
    Securely reads data from a buffer using a user-provided index.
    Checks for valid index range to prevent out-of-bounds access.

    Args:
        buffer: The bytearray buffer to read from.
        index: The integer index to access.

    Returns:
        The integer value at the index if access is valid, otherwise None.
    """
    if not isinstance(buffer, bytearray) or not isinstance(index, int):
        # Enforce type safety
        return None
    
    # Secure bounds check
    if 0 <= index < len(buffer):
        return buffer[index]
    else:
        # Index is out of bounds
        return None

def main():
    """Main function with test cases."""
    buffer_size = 10
    # 1. Dynamically allocate a memory buffer
    buffer = bytearray(i * 10 for i in range(buffer_size))

    print(f"Buffer created with size: {buffer_size}")
    print(f"Buffer content: {list(buffer)}")
    print("--- Running Python Test Cases ---")

    # 2. Test cases
    test_indices = [0, 5, 9, -1, 10]

    for index in test_indices:
        value = secure_read(buffer, index)
        if value is not None:
            print(f"Reading at index {index}: Success! Value = {value}")
        else:
            print(f"Reading at index {index}: Error! Index is out of bounds.")

if __name__ == "__main__":
    main()