def copy_chunk(data: bytes) -> bytes:
    chunk1 = bytearray(data)
    chunk2 = bytearray(len(chunk1))
    chunk2[:] = chunk1
    return bytes(chunk2)

if __name__ == "__main__":
    tests = [
        b"Hello, World!",
        b"foo",
        b"The quick brown fox",
        b"",
        bytes([0, 1, 2, 3, 127, 255]),
    ]
    for t in tests:
        out = copy_chunk(t)
        print(out)