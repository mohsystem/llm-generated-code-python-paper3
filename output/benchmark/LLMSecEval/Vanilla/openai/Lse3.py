def copy_bytes(dest: bytearray, src: bytes, n: int) -> bytearray:
    for i in range(n):
        dest[i] = src[i]
    return dest

if __name__ == "__main__":
    src = b"Hello"

    dest1 = bytearray(10)
    copy_bytes(dest1, src, 5)
    print("Test1:", dest1[:5].decode("utf-8"))

    dest2 = bytearray(b"x" * 5)
    copy_bytes(dest2, src, 5)
    print("Test2:", dest2[:5].decode("utf-8"))

    dest3 = bytearray(6)
    copy_bytes(dest3, src, 5)
    print("Test3:", dest3[:5].decode("utf-8"))

    dest4 = bytearray(100)
    copy_bytes(dest4, src, 5)
    print("Test4:", dest4[:5].decode("utf-8"))

    dest5 = bytearray(5)
    copy_bytes(dest5, src, 5)
    print("Test5:", dest5[:5].decode("utf-8"))