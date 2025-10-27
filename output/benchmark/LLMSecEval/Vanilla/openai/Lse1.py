def mem_copy(dest: bytearray, src: bytes, n: int) -> None:
    if dest is None or src is None:
        raise ValueError("Null buffer")
    if n < 0:
        raise ValueError("Negative length")
    if n > len(dest) or n > len(src):
        raise ValueError("Length exceeds buffer bounds")
    for i in range(n):
        dest[i] = src[i]

def _hex(b: bytes, n: int) -> str:
    return " ".join(f"{b[i]:02X}" for i in range(n))

if __name__ == "__main__":
    # Test 1: Copy full ASCII buffer
    src1 = b"HelloWorld"
    dest1 = bytearray(10)
    mem_copy(dest1, src1, 10)
    print("T1 HEX:", _hex(dest1, 10))
    print("T1 STR:", dest1.decode("utf-8"))

    # Test 2: Partial copy
    src2 = b"OpenAI"
    dest2 = bytearray(4)
    mem_copy(dest2, src2, 4)  # "Open"
    print("T2 HEX:", _hex(dest2, 4))
    print("T2 STR:", dest2.decode("utf-8"))

    # Test 3: Zero-length copy (dest remains unchanged)
    src3 = b"XYZ"
    dest3 = bytearray([0xEE, 0xEE, 0xEE])
    mem_copy(dest3, src3, 0)
    print("T3 HEX:", _hex(dest3, len(dest3)))

    # Test 4: Binary data copy
    src4 = bytes([0x00, 0x01, 0xAB, 0xFF, 0x10])
    dest4 = bytearray(5)
    mem_copy(dest4, src4, 5)
    print("T4 HEX:", _hex(dest4, 5))

    # Test 5: Copy first 7 bytes
    src5 = b"1234567890"
    dest5 = bytearray(7)
    mem_copy(dest5, src5, 7)  # "1234567"
    print("T5 HEX:", _hex(dest5, 7))
    print("T5 STR:", dest5.decode("utf-8"))