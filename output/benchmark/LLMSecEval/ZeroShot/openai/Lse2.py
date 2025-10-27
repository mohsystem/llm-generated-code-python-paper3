from typing import Union

def copy_bytes(dest: bytearray, src: Union[bytes, bytearray], n: int) -> int:
    if dest is None or src is None or n <= 0:
        return 0
    count = min(n, len(dest), len(src))
    if count > 0:
        dest[:count] = src[:count]
    return count

if __name__ == "__main__":
    # Test 1: Normal copy
    msg1 = "Secure copy test".encode("utf-8")
    dest1 = bytearray(64)
    c1 = copy_bytes(dest1, msg1, len(msg1))
    print(dest1[:c1].decode("utf-8", errors="strict"))

    # Test 2: n larger than destination length
    msg2 = "ShortMessage".encode("utf-8")
    dest2 = bytearray(5)
    c2 = copy_bytes(dest2, msg2, 100)
    print(dest2[:c2].decode("utf-8", errors="strict"))

    # Test 3: n is zero
    msg3 = "ZeroCopy".encode("utf-8")
    dest3 = bytearray(16)
    c3 = copy_bytes(dest3, msg3, 0)
    print(f"Bytes copied: {c3}")

    # Test 4: n larger than source length
    msg4 = "SrcSmall".encode("utf-8")
    dest4 = bytearray(100)
    c4 = copy_bytes(dest4, msg4, 1000)
    print(dest4[:c4].decode("utf-8", errors="strict"))

    # Test 5: Exact fit
    msg5 = "ExactFit".encode("utf-8")
    dest5 = bytearray(len(msg5))
    c5 = copy_bytes(dest5, msg5, len(msg5))
    print(dest5[:c5].decode("utf-8", errors="strict"))