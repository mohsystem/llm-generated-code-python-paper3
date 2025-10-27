import os
import sys
import tempfile
import random

MAX_SIZE = 50 * 1024 * 1024  # 50 MB

def process_file(input_path: str, output_path: str):
    if input_path is None or output_path is None:
        raise ValueError("Paths must not be None")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    if os.path.islink(input_path):
        raise OSError(f"Refusing to read from a symbolic link: {input_path}")
    if not os.path.isfile(input_path):
        raise OSError(f"Input is not a regular file: {input_path}")

    size = os.path.getsize(input_path)
    if size < 0 or size > MAX_SIZE:
        raise OSError(f"File size out of allowed range (0..{MAX_SIZE}): {size}")

    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) != size:
        # Defensive: ensure full read
        raise IOError("Could not read the entire file")

    checksum = sum(data) & 0xFFFFFFFF
    is_empty = (checksum == 0)

    parent = os.path.dirname(os.path.abspath(output_path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

    if os.path.exists(output_path) and os.path.islink(output_path):
        raise OSError(f"Refusing to write to a symbolic link: {output_path}")

    with open(output_path, "wb") as f:
        f.write(f"bytes={len(data)}\n".encode("utf-8"))
        f.write(f"checksum={checksum}\n".encode("utf-8"))

    return (len(data), checksum, is_empty)

def _write_bytes(p, b: bytes):
    parent = os.path.dirname(os.path.abspath(p))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    with open(p, "wb") as f:
        f.write(b)

def main():
    try:
        temp_dir = tempfile.mkdtemp(prefix="lse63_py_")

        # Test 1: Empty file
        f1 = os.path.join(temp_dir, "empty.bin")
        _write_bytes(f1, b"")
        r1 = process_file(f1, os.path.join(temp_dir, "out1.txt"))
        print("Test1:", r1)

        # Test 2: Small text
        f2 = os.path.join(temp_dir, "hello.txt")
        _write_bytes(f2, "Hello, world!".encode("utf-8"))
        r2 = process_file(f2, os.path.join(temp_dir, "out2.txt"))
        print("Test2:", r2)

        # Test 3: 2048 random bytes
        f3 = os.path.join(temp_dir, "random.bin")
        _write_bytes(f3, os.urandom(2048))
        r3 = process_file(f3, os.path.join(temp_dir, "out3.txt"))
        print("Test3:", r3)

        # Test 4: 10000 bytes of 0xFF
        f4 = os.path.join(temp_dir, "ff.bin")
        _write_bytes(f4, bytes([0xFF]) * 10000)
        r4 = process_file(f4, os.path.join(temp_dir, "out4.txt"))
        print("Test4:", r4)

        # Test 5: UTF-8 unicode text repeated
        f5 = os.path.join(temp_dir, "utf8.txt")
        _write_bytes(f5, ("こんにちは世界" * 10).encode("utf-8"))
        r5 = process_file(f5, os.path.join(temp_dir, "out5.txt"))
        print("Test5:", r5)
    except Exception as e:
        print("Error:", e, file=sys.stderr)

if __name__ == "__main__":
    main()