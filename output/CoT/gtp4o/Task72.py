# Requires: pip install pycryptodome
from Crypto.Cipher import AES

# Static IV - for demonstration only; avoid static IVs in real systems.
STATIC_IV = bytes([
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB,
    0xCC, 0xDD, 0xEE, 0xFF
])

def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    if block_size <= 0:
        raise ValueError("Invalid block size")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)

def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> bytes:
    if key is None or len(key) not in (16, 24, 32):
        raise ValueError("Key length must be 16, 24, or 32 bytes")
    padded = pad_pkcs7(plaintext, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv=STATIC_IV)
    return cipher.encrypt(padded)

def _to_hex(b: bytes) -> str:
    return ''.join(f'{x:02x}' for x in b)

if __name__ == "__main__":
    # Test case 1
    key1 = bytes(range(16))
    pt1 = b""
    print("TC1:", _to_hex(encrypt_aes_cbc(key1, pt1)))

    # Test case 2
    key2 = bytes([0x01] * 16)
    pt2 = b"A"
    print("TC2:", _to_hex(encrypt_aes_cbc(key2, pt2)))

    # Test case 3
    key3 = b"Sixteen byte key"  # 16 bytes
    pt3 = b"Hello World"
    print("TC3:", _to_hex(encrypt_aes_cbc(key3, pt3)))

    # Test case 4 (AES-192)
    key4 = bytes(range(24))
    pt4 = b"The quick brown fox jumps over the lazy dog"
    print("TC4:", _to_hex(encrypt_aes_cbc(key4, pt4)))

    # Test case 5 (AES-256)
    key5 = bytes(range(32))
    pt5 = b"Data with a length not multiple of block size."
    print("TC5:", _to_hex(encrypt_aes_cbc(key5, pt5)))