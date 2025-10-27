import sys
from typing import BinaryIO, Optional

# Allocates a buffer of exactly 1024 bytes
def allocate_buffer(requested_size: int) -> bytearray:
    FIXED_SIZE = 1024
    return bytearray(FIXED_SIZE)

# Reads up to 10 bytes from the given binary stream into buf[0:n]
# Returns the number of bytes read (0..10), or -1 on error
def read_ten_into(stream: Optional[BinaryIO], buf: Optional[bytearray]) -> int:
    if stream is None or buf is None or len(buf) < 10:
        return -1
    data = stream.read(10)
    if data is None:
        return 0
    n = min(len(data), 10)
    buf[0:n] = data[:n]
    return n

if __name__ == "__main__":
    for i in range(1, 6):
        print(f"Test {i}: Please type at least 10 characters and press Enter:")
        sys.stdout.flush()
        buffer = allocate_buffer(1024)
        # Use binary stdin to read raw bytes safely
        n = read_ten_into(sys.stdin.buffer, buffer)
        if n < 0:
            print("Error: invalid buffer or input stream.")
        else:
            out = buffer[:n].decode('utf-8', errors='replace')
            print(f"Read {n} byte(s): {out}")