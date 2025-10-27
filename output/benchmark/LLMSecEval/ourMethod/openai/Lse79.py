import io
from typing import Tuple, BinaryIO

BUF_SIZE = 1024
READ_100 = 100

def allocate_and_copy_100_twice(stream: BinaryIO) -> Tuple[str, str]:
    if stream is None:
        raise ValueError("stream cannot be None")

    # Allocate buffers
    buf = bytearray(BUF_SIZE)
    buf1 = bytearray(BUF_SIZE)

    n1 = _read_at_most(stream, buf, READ_100)
    n2 = _read_at_most(stream, buf1, READ_100)

    s1 = buf[:n1].decode("utf-8", errors="replace")
    s2 = buf1[:n2].decode("utf-8", errors="replace")
    return s1, s2

def read_up_to_1024(stream: BinaryIO) -> str:
    if stream is None:
        raise ValueError("stream cannot be None")
    buf = bytearray(BUF_SIZE)
    n = _read_at_most(stream, buf, BUF_SIZE)
    return buf[:n].decode("utf-8", errors="replace")

def _read_at_most(stream: BinaryIO, dest: bytearray, max_to_read: int) -> int:
    if max_to_read < 0 or max_to_read > len(dest):
        raise ValueError("invalid max_to_read")
    total = 0
    # Attempt to fill up to max_to_read bytes
    while total < max_to_read:
        chunk = stream.read(max_to_read - total)
        if not chunk:
            break
        # Bound copy into dest
        end = total + len(chunk)
        if end > len(dest):
            # Should never happen due to max_to_read <= len(dest)
            end = len(dest)
            chunk = chunk[: end - total]
        dest[total:end] = chunk
        total = end
    return total

def main() -> None:
    # Test case 1: Less than 100 bytes
    t1 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    s1, s2 = allocate_and_copy_100_twice(io.BytesIO(t1))
    print("T1 buf:", s1)
    print("T1 buf1:", s2)

    # Test case 2: More than 100 bytes (150 'x')
    t2 = b"x" * 150
    s1, s2 = allocate_and_copy_100_twice(io.BytesIO(t2))
    print("T2 buf len:", len(s1))
    print("T2 buf1 len:", len(s2))

    # Test case 3: Empty input
    s1, s2 = allocate_and_copy_100_twice(io.BytesIO(b""))
    print("T3 buf:", repr(s1))
    print("T3 buf1:", repr(s2))

    # Test case 4: read_up_to_1024 with 300 bytes
    t4 = b"y" * 300
    s4 = read_up_to_1024(io.BytesIO(t4))
    print("T4 len:", len(s4))

    # Test case 5: Unicode content
    t5 = ("Hello 你好世界 🙂🚀" * 20).encode("utf-8")
    s1, s2 = allocate_and_copy_100_twice(io.BytesIO(t5))
    print("T5 buf:", s1)
    print("T5 buf1:", s2)

if __name__ == "__main__":
    main()