import io
import sys

def allocate_buffer():
    # Allocates a buffer of 1024 bytes
    return bytearray(1024)

def read_ten_chars_to_buffer(stream, buf):
    """
    Reads up to 10 bytes from the provided binary stream (e.g., sys.stdin.buffer) into buf.
    Returns the number of bytes read.
    """
    if stream is None:
        raise ValueError("stream cannot be None")
    if buf is None:
        raise ValueError("buf cannot be None")
    if len(buf) < 10:
        raise ValueError("buf must be at least 10 bytes long")

    # Ensure we are reading bytes
    data = stream.read(10)
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("stream must be a binary stream returning bytes")

    n = len(data)
    buf[:n] = data
    return n

def main():
    tests = [
        b"HelloWorld!",   # >10
        b"Short",         # <10
        b"1234567890ABC", # >10
        b"",              # empty
        b"ExactTen!!"     # exactly 10
    ]

    for i, t in enumerate(tests, 1):
        buf = allocate_buffer()
        stream = io.BytesIO(t)
        try:
            count = read_ten_chars_to_buffer(stream, buf)
        except Exception as e:
            print(f"Test {i} error: {e}")
            continue
        read_bytes = bytes(buf[:count])
        try:
            decoded = read_bytes.decode('utf-8', errors='replace')
        except Exception:
            decoded = "<decode-error>"
        print(f"Test {i}: readCount={count}, data=\"{decoded}\"")

if __name__ == "__main__":
    main()