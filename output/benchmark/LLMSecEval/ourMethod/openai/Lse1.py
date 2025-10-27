from typing import Union

def mem_copy(dest: bytearray, src: Union[bytes, bytearray], n: int) -> int:
    """
    Copies n bytes from src to dest. Returns number of bytes copied on success, -1 on error.
    """
    if not isinstance(dest, bytearray):
        return -1
    if not isinstance(src, (bytes, bytearray)):
        return -1
    if not isinstance(n, int) or n < 0:
        return -1
    if n > len(dest) or n > len(src):
        return -1
    if n == 0:
        return 0
    # Slice copy is safe and bounded due to checks above
    dest[:n] = src[:n]
    return n

def to_hex(b: Union[bytes, bytearray]) -> str:
    return " ".join(f"{x:02X}" for x in b)

if __name__ == "__main__":
    # Test 1: normal copy of 5 bytes
    src1 = bytearray(range(10))
    dest1 = bytearray(10)
    r1 = mem_copy(dest1, src1, 5)
    print(f"Test1 result={r1} dest1={to_hex(dest1)}")

    # Test 2: copy zero bytes
    src2 = bytes([1,2,3,4,5])
    dest2 = bytearray([9,9,9,9,9])
    r2 = mem_copy(dest2, src2, 0)
    print(f"Test2 result={r2} dest2={to_hex(dest2)}")

    # Test 3: copy full size exact
    src3 = b"ABCDEFGH"
    dest3 = bytearray(8)
    r3 = mem_copy(dest3, src3, 8)
    print(f"Test3 result={r3} dest3={to_hex(dest3)}")

    # Test 4: attempt to copy too many bytes (should fail)
    src4 = bytes([10,20,30,40,50])
    dest4 = bytearray([0,0,0])
    r4 = mem_copy(dest4, src4, 4)
    print(f"Test4 result={r4} dest4={to_hex(dest4)}")

    # Test 5: same object as both src and dest
    same = bytearray([7,7,7,7,7,7])
    r5 = mem_copy(same, same, 6)
    print(f"Test5 result={r5} same={to_hex(same)}")