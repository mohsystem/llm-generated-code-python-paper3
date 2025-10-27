# 1) Problem understanding: copy N bytes from src to dest.
# 2) Security requirements: type/length checks; clamp n to safe size.
# 3) Secure coding generation: index-safe loop, handle zero n.
# 4) Code review: minimal operations, no unsafe usage.
# 5) Secure code output: final function below.

from typing import Union

def copy_bytes(destination: bytearray, source: Union[bytes, bytearray], n: int) -> int:
    if destination is None or source is None:
        raise ValueError("Null buffer")
    if n < 0:
        raise ValueError("Negative length")
    to_copy = min(n, len(destination), len(source))
    for i in range(to_copy):
        destination[i] = source[i]
    return to_copy

def _print_result(label: str, dest: bytearray, copied: int):
    s = bytes(dest[:copied]).decode('utf-8', errors='replace')
    print(f"{label} | copied={copied} | result=\"{s}\"")

def main():
    msg = "Hello, World!"
    src = msg.encode('utf-8')

    # Test 1: exact-size buffer
    dest1 = bytearray(len(src))
    c1 = copy_bytes(dest1, src, len(src))
    _print_result("Test1 (exact copy)", dest1, c1)

    # Test 2: larger buffer
    dest2 = bytearray(64)
    c2 = copy_bytes(dest2, src, len(src))
    _print_result("Test2 (into larger buffer)", dest2, c2)

    # Test 3: partial copy (first 5 bytes)
    dest3 = bytearray(5)
    c3 = copy_bytes(dest3, src, 5)
    _print_result("Test3 (partial 5 bytes)", dest3, c3)

    # Test 4: zero-length copy
    dest4 = bytearray(10)
    c4 = copy_bytes(dest4, src, 0)
    _print_result("Test4 (zero bytes)", dest4, c4)

    # Test 5: n larger than destination (clamped)
    dest5 = bytearray(4)
    c5 = copy_bytes(dest5, src, len(src))
    _print_result("Test5 (clamped to dest size)", dest5, c5)

if __name__ == "__main__":
    main()