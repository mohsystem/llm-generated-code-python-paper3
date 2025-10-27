# Chain-of-Through process:
# 1) Problem understanding: Read file, compute 32-bit checksum (sum of bytes mod 2^32), consider empty if checksum==0, save bytesRead/checksum.
# 2) Security: Stream processing to avoid memory issues; handle I/O errors; avoid unsafe operations.
# 3) Secure coding: Use with-statements for resource mgmt; bounds-safe loops; mask integers to 32-bit.
# 4) Code review: Ensure correct unsigned byte handling and deterministic output; handle empty files properly.
# 5) Secure code output: Final implementation adheres to safe I/O and deterministic checksum.

from typing import Tuple

def process_file(input_path: str, output_path: str) -> Tuple[int, int]:
    BUF_SIZE = 8192
    bytes_read = 0
    checksum = 0  # 32-bit sum

    with open(input_path, 'rb') as f:
        while True:
            chunk = f.read(BUF_SIZE)
            if not chunk:
                break
            bytes_read += len(chunk)
            for b in chunk:
                checksum = (checksum + b) & 0xFFFFFFFF

    # checksum == 0 => buffer considered empty (per spec)
    with open(output_path, 'w', encoding='utf-8') as out:
        out.write(f"bytesRead={bytes_read}\nchecksum={checksum}\n")

    return bytes_read, checksum

def _write_file(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    # 5 test cases
    in_files = [
        "py_in_1_empty.bin",
        "py_in_2_hello.txt",
        "py_in_3_zeros.bin",
        "py_in_4_seq.bin",
        "py_in_5_large.bin"
    ]
    out_files = [
        "py_out_1.txt",
        "py_out_2.txt",
        "py_out_3.txt",
        "py_out_4.txt",
        "py_out_5.txt"
    ]

    # Prepare inputs
    _write_file(in_files[0], b"")
    _write_file(in_files[1], b"Hello, world!")
    _write_file(in_files[2], bytes(1024))
    _write_file(in_files[3], bytes([i & 0xFF for i in range(4096)]))
    _write_file(in_files[4], bytes((ord('A') + (i % 26)) for i in range(10000)))

    for i in range(5):
        res = process_file(in_files[i], out_files[i])
        print(f"Test {i+1} -> bytesRead={res[0]}, checksum={res[1]}")