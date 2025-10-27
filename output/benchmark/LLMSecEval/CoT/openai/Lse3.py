# Step 1-5: Secure byte copy with validation and overlap-safety using a temporary buffer.
def copy_bytes(dest: bytearray, src, n: int) -> int:
    if not isinstance(dest, bytearray) or src is None or n <= 0:
        return 0
    if not isinstance(src, (bytes, bytearray)):
        return 0
    bytes_to_copy = min(n, len(dest), len(src))
    if bytes_to_copy <= 0:
        return 0
    temp = bytes(src[:bytes_to_copy])  # ensures overlap-safety
    dest[0:bytes_to_copy] = temp
    return bytes_to_copy
# End of secure copy

def _to_str(barr: bytearray, count: int) -> str:
    return barr[:max(0, min(count, len(barr)))].decode('utf-8', errors='ignore')

def main():
    # Test 1: Copy "Hello" (5 bytes)
    dest1 = bytearray(16)
    src1 = b"Hello"
    c1 = copy_bytes(dest1, src1, 5)
    print(f"Test1 bytesCopied={c1} content=\"{_to_str(dest1, c1)}\"")

    # Test 2: Request more than source length (10) - clamp to 5
    dest2 = bytearray(16)
    c2 = copy_bytes(dest2, src1, 10)
    print(f"Test2 bytesCopied={c2} content=\"{_to_str(dest2, c2)}\"")

    # Test 3: Destination smaller (3)
    dest3 = bytearray(3)
    c3 = copy_bytes(dest3, src1, 5)
    print(f"Test3 bytesCopied={c3} content=\"{_to_str(dest3, c3)}\"")

    # Test 4: Zero length copy
    dest4 = bytearray(10)
    c4 = copy_bytes(dest4, src1, 0)
    print(f"Test4 bytesCopied={c4} content=\"{_to_str(dest4, c4)}\"")

    # Test 5: None source
    dest5 = bytearray(10)
    c5 = copy_bytes(dest5, None, 5)
    print(f"Test5 bytesCopied={c5} content=\"{_to_str(dest5, c5)}\"")

if __name__ == "__main__":
    main()