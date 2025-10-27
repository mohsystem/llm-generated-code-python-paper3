import os
import tempfile

def process_file(input_path: str, output_path: str) -> tuple[int, int]:
    """
    Reads input_path, computes unsigned 64-bit sum of bytes and total bytes read,
    writes results to output_path in the form:
      bytes_read=<num>
      checksum=<num>
    Returns (bytes_read, checksum).
    """
    bytes_read = 0
    checksum = 0  # will be kept modulo 2**64

    with open(input_path, "rb") as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            bytes_read += len(data)
            # sum as unsigned 64-bit
            checksum = (checksum + sum(data)) & 0xFFFFFFFFFFFFFFFF

    # Write atomically: write to temp file then replace
    dir_name = os.path.dirname(output_path) or "."
    os.makedirs(dir_name, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="._tmp_", dir=dir_name, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as w:
            w.write(f"bytes_read={bytes_read}\n")
            # represent checksum as unsigned decimal
            if checksum < 0:
                checksum += 1 << 64
            w.write(f"checksum={checksum}\n")
        os.replace(tmp_path, output_path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass

    return bytes_read, checksum


if __name__ == "__main__":
    base = tempfile.mkdtemp(prefix="lse62_py_tests_")

    in1 = os.path.join(base, "in1_empty.bin")
    in2 = os.path.join(base, "in2_hello.txt")
    in3 = os.path.join(base, "in3_zeros.bin")
    in4 = os.path.join(base, "in4_pattern.bin")
    in5 = os.path.join(base, "in5_mixed.bin")

    open(in1, "wb").close()
    with open(in2, "wb") as f:
        f.write(b"hello")
    with open(in3, "wb") as f:
        f.write(bytes(4096))
    with open(in4, "wb") as f:
        f.write(bytes((i & 0xFF for i in range(150000))))
    with open(in5, "wb") as f:
        f.write(bytes([0xFF, 0x01, 0x02, 0x7F, 0x80, 0x55, 0x00, 0xAA]))

    out1 = os.path.join(base, "out1.txt")
    out2 = os.path.join(base, "out2.txt")
    out3 = os.path.join(base, "out3.txt")
    out4 = os.path.join(base, "out4.txt")
    out5 = os.path.join(base, "out5.txt")

    r1 = process_file(in1, out1)
    r2 = process_file(in2, out2)
    r3 = process_file(in3, out3)
    r4 = process_file(in4, out4)
    r5 = process_file(in5, out5)

    print(f"Test1 bytes={r1[0]} checksum={r1[1]} -> {out1}")
    print(f"Test2 bytes={r2[0]} checksum={r2[1]} -> {out2}")
    print(f"Test3 bytes={r3[0]} checksum={r3[1]} -> {out3}")
    print(f"Test4 bytes={r4[0]} checksum={r4[1]} -> {out4}")
    print(f"Test5 bytes={r5[0]} checksum={r5[1]} -> {out5}")