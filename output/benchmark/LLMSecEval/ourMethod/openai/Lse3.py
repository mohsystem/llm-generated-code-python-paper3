from typing import ByteString

def copy_bytes(dest: bytearray, src: ByteString, n: int) -> int:
    if not isinstance(dest, bytearray):
        raise TypeError("dest must be a bytearray")
    if not isinstance(src, (bytes, bytearray, memoryview)):
        raise TypeError("src must be bytes-like")
    if not isinstance(n, int) or n < 0:
        raise ValueError("n must be a non-negative integer")
    m = min(n, len(dest), len(src))
    if m > 0:
        dest[:m] = src[:m]
    return m

if __name__ == "__main__":
    hello = b"Hello"

    # Test 1: Exact fit
    dest1 = bytearray(5)
    copied1 = copy_bytes(dest1, hello, 5)
    print(f"Test1 copied: {copied1} data: {dest1[:copied1].decode('utf-8', errors='strict')}")

    # Test 2: Destination smaller than requested
    dest2 = bytearray(3)
    copied2 = copy_bytes(dest2, hello, 5)
    print(f"Test2 copied: {copied2} data: {dest2[:copied2].decode('utf-8', errors='strict')}")

    # Test 3: Destination larger than requested (exact request)
    dest3 = bytearray(10)
    copied3 = copy_bytes(dest3, hello, 5)
    print(f"Test3 copied: {copied3} data: {dest3[:copied3].decode('utf-8', errors='strict')}")

    # Test 4: Copy fewer bytes than available
    dest4 = bytearray(10)
    copied4 = copy_bytes(dest4, hello, 3)
    print(f"Test4 copied: {copied4} data: {dest4[:copied4].decode('utf-8', errors='strict')}")

    # Test 5: Copy zero bytes
    dest5 = bytearray(5)
    copied5 = copy_bytes(dest5, hello, 0)
    print(f"Test5 copied: {copied5} data: {dest5[:copied5].decode('utf-8', errors='strict')}")