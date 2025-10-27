from typing import Optional, Union

# Copy n bytes from src to dest. Returns number of bytes copied, or -1 on error.
def copy_bytes(dest: bytearray, src: Union[bytes, bytearray], n: int) -> int:
    if not isinstance(dest, bytearray):
        return -1
    if not isinstance(src, (bytes, bytearray)):
        return -1
    if n < 0:
        return -1
    if n == 0:
        return 0
    if dest is None or src is None:
        return -1
    if len(dest) < n or len(src) < n:
        return -1

    # Perform copy safely
    # Handle potential overlap if dest and src refer to same underlying object
    if dest is src:
        temp = bytes(src[:n])
        dest[:n] = temp
    else:
        dest[:n] = src[:n]
    return n

if __name__ == "__main__":
    # Test 1: Normal copy of "Hello"
    src1 = b"Hello"
    dest1 = bytearray(10)
    r1 = copy_bytes(dest1, src1, 5)
    print(f"Test1 result={r1} dest='{dest1[:5].decode()}'")

    # Test 2: Dest too small (should fail)
    dest2 = bytearray(3)
    r2 = copy_bytes(dest2, src1, 5)
    print(f"Test2 result={r2}")

    # Test 3: Exact size buffer for "Hello"
    dest3 = bytearray(5)
    r3 = copy_bytes(dest3, src1, 5)
    print(f"Test3 result={r3} dest='{bytes(dest3).decode()}'")

    # Test 4: Copy 0 bytes (no-op)
    dest4 = bytearray(2)
    r4 = copy_bytes(dest4, src1, 0)
    print(f"Test4 result={r4}")

    # Test 5: Overlap scenario using the same buffer
    buf = bytearray(b"HelloWorld")
    r5 = copy_bytes(buf[5:], buf, 5)  # copy "Hello" into position 5-9
    print(f"Test5 result={r5} buf='{buf.decode()}'")