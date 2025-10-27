def copy_bytes(destination: bytearray, source: bytes, n: int):
    """
    Copies n bytes from the source to the destination.
    """
    # Ensure we don't go out of bounds
    length = min(n, len(destination), len(source))
    for i in range(length):
        destination[i] = source[i]
    return destination

def main():
    # Test Case 1: Basic full copy
    print("--- Test Case 1: Basic full copy ---")
    src1 = b'\x01\x02\x03\x04\x05'
    dest1 = bytearray(5)
    print(f"Before: dest1 = {list(dest1)}")
    copy_bytes(dest1, src1, 5)
    print(f"After:  dest1 = {list(dest1)}")
    print()

    # Test Case 2: Partial copy
    print("--- Test Case 2: Partial copy ---")
    src2 = b'\x0a\x14\x1e\x28\x32'  # 10, 20, 30, 40, 50
    dest2 = bytearray([99, 98, 97, 96, 95])
    print(f"Before: dest2 = {list(dest2)}")
    copy_bytes(dest2, src2, 3)
    print(f"After:  dest2 = {list(dest2)}")
    print()

    # Test Case 3: Zero-length copy
    print("--- Test Case 3: Zero-length copy ---")
    src3 = b'\x01\x01\x01'
    dest3 = bytearray([2, 2, 2])
    print(f"Before: dest3 = {list(dest3)}")
    copy_bytes(dest3, src3, 0)
    print(f"After:  dest3 = {list(dest3)}")
    print()

    # Test Case 4: Full overwrite of a smaller source into a larger destination
    print("--- Test Case 4: Overwriting a larger destination ---")
    src4 = b'\x07\x08'
    dest4 = bytearray([1, 2, 3, 4])
    print(f"Before: dest4 = {list(dest4)}")
    copy_bytes(dest4, src4, 2)
    print(f"After:  dest4 = {list(dest4)}")
    print()

    # Test Case 5: Copying into a larger buffer
    print("--- Test Case 5: Copying into a larger buffer ---")
    src5 = b'\x01\x02\x03'
    dest5 = bytearray(6)
    print(f"Before: dest5 = {list(dest5)}")
    copy_bytes(dest5, src5, 3)
    print(f"After:  dest5 = {list(dest5)}")
    print()

if __name__ == "__main__":
    main()