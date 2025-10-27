from typing import ByteString

def copy_bytes(dest: bytearray, src: ByteString, n: int) -> bytearray:
    length = min(n, len(dest), len(src))
    dest[:length] = src[:length]
    return dest

if __name__ == "__main__":
    tests = [
        (b"Hello, World!", 13, 20),
        (b"Hello, World!", 5, 5),
        (b"Data", 4, 10),
        (b"ByteCopy", 0, 10),
        (b"Sample", 6, 6),
    ]

    for i, (src, n, dest_size) in enumerate(tests, 1):
        dest = bytearray(dest_size)
        copy_bytes(dest, src, n)
        print(f'Test {i}: "{dest[:n].decode("utf-8", "ignore")}"')