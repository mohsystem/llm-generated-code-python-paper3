import os
import sys

class ChaCha20:
    SIGMA = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

    def __init__(self, key: bytes, nonce: bytes, counter: int = 1):
        if key is None or len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        if nonce is None or len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        self.state = [0] * 16
        self.state[0:4] = self.SIGMA
        for i in range(8):
            self.state[4 + i] = int.from_bytes(key[i*4:(i+1)*4], 'little')
        self.state[12] = counter & 0xffffffff
        self.state[13] = int.from_bytes(nonce[0:4], 'little')
        self.state[14] = int.from_bytes(nonce[4:8], 'little')
        self.state[15] = int.from_bytes(nonce[8:12], 'little')
        self._buf = bytearray(64)
        self._pos = 64

    @staticmethod
    def _rotl(v, c):
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def _qr(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = ChaCha20._rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = ChaCha20._rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = ChaCha20._rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = ChaCha20._rotl(x[b] ^ x[c], 7)

    def _gen_block(self):
        x = self.state[:]
        for _ in range(10):
            self._qr(x, 0, 4, 8, 12)
            self._qr(x, 1, 5, 9, 13)
            self._qr(x, 2, 6, 10, 14)
            self._qr(x, 3, 7, 11, 15)
            self._qr(x, 0, 5, 10, 15)
            self._qr(x, 1, 6, 11, 12)
            self._qr(x, 2, 7, 8, 13)
            self._qr(x, 3, 4, 9, 14)
        for i in range(16):
            y = (x[i] + self.state[i]) & 0xffffffff
            self._buf[i*4:(i+1)*4] = y.to_bytes(4, 'little')
        self.state[12] = (self.state[12] + 1) & 0xffffffff
        self._pos = 0

    def xor_bytes(self, data: bytes) -> bytes:
        out = bytearray(data)
        self.xor_inplace(out)
        return bytes(out)

    def xor_inplace(self, buf: bytearray):
        i = 0
        n = len(buf)
        while i < n:
            if self._pos >= 64:
                self._gen_block()
            take = min(64 - self._pos, n - i)
            for j in range(take):
                buf[i + j] ^= self._buf[self._pos + j]
            self._pos += take
            i += take

def chacha20_xor_bytes(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    return ChaCha20(key, nonce, counter).xor_bytes(data)

def encrypt_file(input_path: str, output_path: str, key: bytes, nonce: bytes) -> bool:
    return _stream_xor_file(input_path, output_path, key, nonce, 1)

def decrypt_file(input_path: str, output_path: str, key: bytes, nonce: bytes) -> bool:
    return _stream_xor_file(input_path, output_path, key, nonce, 1)

def _stream_xor_file(input_path: str, output_path: str, key: bytes, nonce: bytes, counter: int) -> bool:
    try:
        if key is None or len(key) != 32 or nonce is None or len(nonce) != 12:
            return False
        ctx = ChaCha20(key, nonce, counter)
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            while True:
                chunk = fin.read(8192)
                if not chunk:
                    break
                buf = bytearray(chunk)
                ctx.xor_inplace(buf)
                fout.write(buf)
        return True
    except Exception:
        return False

def _pattern_bytes(n: int) -> bytes:
    return bytes((i & 0xff for i in range(n)))

if __name__ == "__main__":
    key = bytes(((i * 7 + 3) & 0xff for i in range(32)))
    nonce = bytes(((i * 5 + 1) & 0xff for i in range(12)))
    tmp = os.getenv('TMPDIR') or os.getenv('TEMP') or '/tmp'
    sizes = [0, 13, 65, 1000, 50000]
    all_ok = True
    for t in range(5):
        in_path = os.path.join(tmp, f"py_in_{t}.bin")
        enc_path = os.path.join(tmp, f"py_enc_{t}.bin")
        dec_path = os.path.join(tmp, f"py_dec_{t}.bin")
        if t == 1:
            content = b"Hello, world!"
        else:
            content = _pattern_bytes(sizes[t])
        with open(in_path, 'wb') as f:
            f.write(content)
        ok1 = encrypt_file(in_path, enc_path, key, nonce)
        ok2 = decrypt_file(enc_path, dec_path, key, nonce)
        ok3 = False
        if ok1 and ok2:
            with open(dec_path, 'rb') as f:
                ok3 = f.read() == content
        print(f"Test {t}: {'OK' if (ok1 and ok2 and ok3) else 'FAIL'}")
        all_ok &= (ok1 and ok2 and ok3)
        try:
            os.unlink(in_path)
            os.unlink(enc_path)
            os.unlink(dec_path)
        except Exception:
            pass
    print(f"All tests: {'PASS' if all_ok else 'FAIL'}")