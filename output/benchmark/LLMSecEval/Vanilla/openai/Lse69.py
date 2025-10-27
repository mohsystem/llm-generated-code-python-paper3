import base64
import os

def upload_image(src_path: str, out_base64_path: str) -> str:
    with open(src_path, 'rb') as f:
        data = f.read()
    encoded = base64.b64encode(data).decode('ascii')
    with open(out_base64_path, 'w', encoding='utf-8') as f:
        f.write(encoded)
    return encoded

def _write_bytes(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    samples = [
        bytes(range(0, 16)),
        bytes([0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43, 0x11]),
        b"\x89PNG\r\n\x1a\n\x00\x00\x00IDAT",
        b"Hello from Python!",
        bytes([0x00, 0xFF, 0xAA, 0x55, 0xCC, 0x33, 0x77, 0x88, 0x99, 0x10])
    ]
    srcs = [f"py_img{i+1}.bin" for i in range(5)]
    outs = [f"py_img{i+1}.b64" for i in range(5)]

    for i in range(5):
        _write_bytes(srcs[i], samples[i])
        b64 = upload_image(srcs[i], outs[i])
        print(f"Test {i+1}: src={srcs[i]}, out={outs[i]}, b64_len={len(b64)}")