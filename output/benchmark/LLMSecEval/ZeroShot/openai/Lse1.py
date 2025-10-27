from typing import Union

def memmove_bytes(dest: bytearray, src: Union[bytes, bytearray], count: int) -> bytearray:
    if dest is None or src is None:
        raise ValueError("Source and destination must not be None")
    if not isinstance(dest, bytearray):
        raise TypeError("Destination must be a bytearray")
    if not isinstance(src, (bytes, bytearray)):
        raise TypeError("Source must be bytes or bytearray")
    if count < 0:
        raise ValueError("Count must be non-negative")
    if count > len(dest) or count > len(src):
        raise ValueError("Count exceeds buffer length")
    if count == 0:
        return dest
    # Use a temporary copy to ensure correct behavior even if src and dest refer to the same underlying buffer.
    temp = bytes(src[:count])
    dest[:count] = temp
    return dest

def _to_hex(buf: bytes) -> str:
    return " ".join(f"{b:02X}" for b in buf)

if __name__ == "__main__":
    # Test 1: Copy 10 bytes "HelloWorld"
    dest1 = bytearray(10)
    src1 = b"HelloWorld"
    memmove_bytes(dest1, src1, 10)
    print("Test1:", dest1.decode("utf-8", errors="ignore"))

    # Test 2: Copy 3 bytes from "abcdef"
    dest2 = bytearray(6)
    src2 = b"abcdef"
    memmove_bytes(dest2, src2, 3)
    print("Test2:", dest2.decode("utf-8", errors="ignore"), "| Hex:", _to_hex(dest2))

    # Test 3: Zero bytes copy (no change)
    dest3 = bytearray(3)
    src3 = b"xyz"
    memmove_bytes(dest3, src3, 0)
    print("Test3:", list(dest3), "| Hex:", _to_hex(dest3))

    # Test 4: Invalid count (exceeds dest)
    try:
        dest4 = bytearray(2)
        src4 = b"12345"
        memmove_bytes(dest4, src4, 5)
        print("Test4: Should not reach here")
    except ValueError as ex:
        print("Test4: Caught exception -", ex)

    # Test 5: Same object as src and dest
    both = bytearray(b"12345")
    memmove_bytes(both, both, 4)
    print("Test5:", both.decode("utf-8", errors="ignore"))