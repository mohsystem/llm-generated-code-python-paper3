import sys
import io

def allocate_buffer():
    return bytearray(1024)

def read_10_chars_into_buf(buf):
    data = sys.stdin.buffer.read(10)
    n = len(data)
    buf[:n] = data
    return n

if __name__ == "__main__":
    tests = [
        b"abcdefghij",
        b"1234567890",
        b"short",
        b"tenchars!!",
        b"with newline\nmore"
    ]
    for i, data in enumerate(tests, 1):
        sys.stdin = io.TextIOWrapper(io.BytesIO(data), encoding='utf-8')
        buf = allocate_buffer()
        n = read_10_chars_into_buf(buf)
        print(f"Test{i}: {bytes(buf[:n]).decode('utf-8', errors='ignore')}")