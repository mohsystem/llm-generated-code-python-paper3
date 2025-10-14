import os

def _ensure_bytes_key(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if not key:
        raise ValueError("Key must not be empty")
    return key

def encrypt_file(input_path, output_path, key):
    key = _ensure_bytes_key(key)
    total = 0
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        buf_size = 65536
        key_len = len(key)
        ki = 0
        while True:
            chunk = f_in.read(buf_size)
            if not chunk:
                break
            data = bytearray(chunk)
            for i in range(len(data)):
                data[i] ^= key[ki]
                ki += 1
                if ki == key_len:
                    ki = 0
            f_out.write(data)
            total += len(data)
    return total

def decrypt_file(input_path, output_path, key):
    return encrypt_file(input_path, output_path, key)

def _write_bytes(path, data: bytes):
    with open(path, 'wb') as f:
        f.write(data)

def _read_bytes(path):
    with open(path, 'rb') as f:
        return f.read()

def _files_equal(a, b):
    return _read_bytes(a) == _read_bytes(b)

if __name__ == '__main__':
    # Test case 1: simple text
    in1, enc1, dec1 = 'py_in1.txt', 'py_in1.enc', 'py_in1.dec'
    _write_bytes(in1, b'Hello, World!')
    encrypt_file(in1, enc1, 'alpha')
    decrypt_file(enc1, dec1, 'alpha')
    print('Test1 OK:', _files_equal(in1, dec1))

    # Test case 2: unicode text
    in2, enc2, dec2 = 'py_in2.txt', 'py_in2.enc', 'py_in2.dec'
    _write_bytes(in2, 'こんにちは世界 🌍🚀'.encode('utf-8'))
    encrypt_file(in2, enc2, 'beta鍵')
    decrypt_file(enc2, dec2, 'beta鍵')
    print('Test2 OK:', _files_equal(in2, dec2))

    # Test case 3: larger content
    in3, enc3, dec3 = 'py_in3.txt', 'py_in3.enc', 'py_in3.dec'
    content3 = ('The quick brown fox jumps over the lazy dog.\n' * 20000).encode('utf-8')
    _write_bytes(in3, content3)
    encrypt_file(in3, enc3, 'gamma_secret_12345')
    decrypt_file(enc3, dec3, 'gamma_secret_12345')
    print('Test3 OK:', _files_equal(in3, dec3))

    # Test case 4: binary data
    in4, enc4, dec4 = 'py_in4.bin', 'py_in4.enc', 'py_in4.dec'
    data4 = bytes([i % 256 for i in range(4096)])
    _write_bytes(in4, data4)
    encrypt_file(in4, enc4, b'\x00\xFF\x10\x20delta')
    decrypt_file(enc4, dec4, b'\x00\xFF\x10\x20delta')
    print('Test4 OK:', _files_equal(in4, dec4))

    # Test case 5: empty file
    in5, enc5, dec5 = 'py_in5.empty', 'py_in5.enc', 'py_in5.dec'
    _write_bytes(in5, b'')
    encrypt_file(in5, enc5, 'epsilon')
    decrypt_file(enc5, dec5, 'epsilon')
    print('Test5 OK:', _files_equal(in5, dec5))