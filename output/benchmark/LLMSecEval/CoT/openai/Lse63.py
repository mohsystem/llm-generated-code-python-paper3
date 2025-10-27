import os
import tempfile

def process_file(input_path: str, output_path: str):
    with open(input_path, 'rb') as f:
        data = f.read()

    checksum = sum(data) & 0xFFFFFFFF
    is_empty = (checksum == 0)

    os.makedirs(os.path.dirname(output_path), exist_ok=True) if os.path.dirname(output_path) else None
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"bytes_read={len(data)}\n")
        f.write(f"checksum={checksum}\n")

    return {"bytes_read": len(data), "checksum": checksum, "empty": is_empty}

if __name__ == "__main__":
    tmp_dir = tempfile.mkdtemp(prefix="lse63_py_demo_")

    tests = [
        ("empty.bin", b""),
        ("hello.txt", b"hello"),
        ("repeatA.bin", b"a" * 1024),
        ("binary.bin", bytes([0x01, 0x02, 0xFF, 0x10, 0x20, 0x7F])),
        ("unicode.txt", "こんにちは".encode("utf-8")),
    ]

    for i, (name, content) in enumerate(tests, 1):
        in_path = os.path.join(tmp_dir, name)
        out_path = os.path.join(tmp_dir, name + ".out.txt")
        with open(in_path, "wb") as f:
            f.write(content)
        res = process_file(in_path, out_path)
        print(f"Test {i}: {in_path} -> bytes={res['bytes_read']}, checksum={res['checksum']}, empty={res['empty']} | out={out_path}")

    print("Output dir:", tmp_dir)