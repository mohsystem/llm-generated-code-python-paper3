import os

def process_file(input_path: str, output_path: str):
    with open(input_path, 'rb') as f:
        data = f.read()
    bytes_read = len(data)
    checksum = sum(data) & 0xFFFFFFFF
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"bytes={bytes_read}\nchecksum={checksum}\n")
    return bytes_read, checksum

if __name__ == "__main__":
    # Test case 1: Empty file
    in1, out1 = "py_in1.bin", "py_out1.txt"
    with open(in1, 'wb') as f: f.write(b"")
    print("Test1 ->", process_file(in1, out1))

    # Test case 2: "Hello, World!"
    in2, out2 = "py_in2.bin", "py_out2.txt"
    with open(in2, 'wb') as f: f.write(b"Hello, World!")
    print("Test2 ->", process_file(in2, out2))

    # Test case 3: bytes 1..100
    in3, out3 = "py_in3.bin", "py_out3.txt"
    with open(in3, 'wb') as f: f.write(bytes(range(1, 101)))
    print("Test3 ->", process_file(in3, out3))

    # Test case 4: 10 zero bytes
    in4, out4 = "py_in4.bin", "py_out4.txt"
    with open(in4, 'wb') as f: f.write(bytes([0]*10))
    print("Test4 ->", process_file(in4, out4))

    # Test case 5: "abc" repeated 1000 times
    in5, out5 = "py_in5.bin", "py_out5.txt"
    with open(in5, 'wb') as f: f.write(("abc"*1000).encode('utf-8'))
    print("Test5 ->", process_file(in5, out5))