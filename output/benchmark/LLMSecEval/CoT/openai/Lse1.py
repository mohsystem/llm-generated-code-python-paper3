from typing import Union

def copy_bytes(dest: bytearray, src: Union[bytes, bytearray], n: int) -> bytearray:
    if dest is None or src is None:
        raise ValueError("Destination and source cannot be None.")
    if n < 0:
        raise ValueError("Number of bytes to copy cannot be negative.")
    if n > len(dest) or n > len(src):
        raise ValueError("Insufficient buffer size for copy operation.")
    if n == 0 or dest is src:
        return dest
    # Use slicing which safely handles overlapping in Python's managed memory
    dest[:n] = src[:n]
    return dest

def _print_bytes(label: str, b: Union[bytes, bytearray], n: int):
    print(f"{label}: [{', '.join(str(int(x)) for x in b[:n])}]")

def main():
    # Test 1: Basic copy
    src1 = bytes([1, 2, 3, 4, 5])
    dst1 = bytearray(5)
    copy_bytes(dst1, src1, 5)
    _print_bytes("Test1 dest", dst1, 5)

    # Test 2: Zero-length copy
    src2 = bytes([7, 8, 9])
    dst2 = bytearray([9, 9, 9])
    copy_bytes(dst2, src2, 0)
    _print_bytes("Test2 dest", dst2, 3)

    # Test 3: Partial copy
    src3 = bytes([10, 20, 30])
    dst3 = bytearray(5)
    copy_bytes(dst3, src3, 3)
    _print_bytes("Test3 dest", dst3, 5)

    # Test 4: Same object as both src and dest
    buf4 = bytearray([5, 4, 3, 2, 1])
    copy_bytes(buf4, buf4, 5)
    _print_bytes("Test4 dest", buf4, 5)

    # Test 5: Bounds error handling
    try:
        src5 = bytes([1, 2, 3])
        dst5 = bytearray(2)
        copy_bytes(dst5, src5, 3)
    except ValueError as ex:
        print(f"Test5 caught exception: {ex}")

if __name__ == "__main__":
    main()