import os

def process_file(input_path: str, output_path: str):
    with open(input_path, 'rb') as f:
        data = f.read()
    bytes_read = len(data)
    checksum = sum(data) & 0xFFFFFFFF
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"bytes={bytes_read}\nchecksum={checksum}\n")
    return bytes_read, checksum

def write_bytes(path: str, data: bytes):
    with open(path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    # Test case 1: Empty file
    in1 = "py_in1.bin"
    out1 = "py_out1.txt"
    write_bytes(in1, b"")
    r1 = process_file(in1, out1)
    print(f"Test 1 -> bytes={r1[0]}, checksum={r1[1]}, saved: {out1}")

    # Test case 2: "Hello, world!"
    in2 = "py_in2.bin"
    out2 = "py_out2.txt"
    write_bytes(in2, b"Hello, world!")
    r2 = process_file(in2, out2)
    print(f"Test 2 -> bytes={r2[0]}, checksum={r2[1]}, saved: {out2}")

    # Test case 3: 1024 bytes 0..255 repeating
    in3 = "py_in3.bin"
    out3 = "py_out3.txt"
    data3 = bytes([i & 0xFF for i in range(1024)])
    write_bytes(in3, data3)
    r3 = process_file(in3, out3)
    print(f"Test 3 -> bytes={r3[0]}, checksum={r3[1]}, saved: {out3}")

    # Test case 4: Non-ASCII pattern repeated
    in4 = "py_in4.bin"
    out4 = "py_out4.txt"
    pattern4 = bytes([0x00, 0xFF, 0x10, 0x7F, 0x80])
    data4 = (pattern4 * (100 // len(pattern4) + 1))[:100]
    write_bytes(in4, data4)
    r4 = process_file(in4, out4)
    print(f"Test 4 -> bytes={r4[0]}, checksum={r4[1]}, saved: {out4}")

    # Test case 5: 4096 bytes deterministic generator
    in5 = "py_in5.bin"
    out5 = "py_out5.txt"
    data5 = bytes(((i * 31 + 7) & 0xFF) for i in range(4096))
    write_bytes(in5, data5)
    r5 = process_file(in5, out5)
    print(f"Test 5 -> bytes={r5[0]}, checksum={r5[1]}, saved: {out5}")