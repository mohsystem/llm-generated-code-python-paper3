# Chain-of-Through Step 1: Problem understanding
# - Implement XTEA in CTR mode with 128-bit key (16 bytes) and 64-bit nonce.
# Step 2: Security requirements
# - Enforce key length, require explicit nonce, no RNG in function.
# Step 3: Secure coding generation
# - Use 32-bit masking to simulate unsigned 32-bit arithmetic.
# Step 4: Code review with careful masking and bounds.
# Step 5: Secure output.

from typing import List

def _key_to_words_le(key_bytes: bytes) -> List[int]:
    return [
        key_bytes[0] | (key_bytes[1] << 8) | (key_bytes[2] << 16) | (key_bytes[3] << 24),
        key_bytes[4] | (key_bytes[5] << 8) | (key_bytes[6] << 16) | (key_bytes[7] << 24),
        key_bytes[8] | (key_bytes[9] << 8) | (key_bytes[10] << 16) | (key_bytes[11] << 24),
        key_bytes[12] | (key_bytes[13] << 8) | (key_bytes[14] << 16) | (key_bytes[15] << 24),
    ]

def _xtea_encrypt_block(v0: int, v1: int, k: List[int]) -> (int, int):
    mask = 0xFFFFFFFF
    v0 &= mask
    v1 &= mask
    sum_ = 0
    delta = 0x9E3779B9
    for _ in range(32):
        v0 = (v0 + (((((v1 << 4) & mask) ^ (v1 >> 5)) + v1) ^ ((sum_ + (k[sum_ & 3] & mask)) & mask))) & mask
        sum_ = (sum_ + delta) & mask
        v1 = (v1 + (((((v0 << 4) & mask) ^ (v0 >> 5)) + v0) ^ ((sum_ + (k[(sum_ >> 11) & 3] & mask)) & mask))) & mask
    return v0, v1

def _int_pair_to_bytes_le(a: int, b: int) -> bytes:
    return bytes((
        a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF,
        b & 0xFF, (b >> 8) & 0xFF, (b >> 16) & 0xFF, (b >> 24) & 0xFF,
    ))

def _to_hex(data: bytes) -> str:
    return data.hex()

def encrypt_message(message: str, key16: str, nonce: int) -> str:
    if message is None or key16 is None:
        raise ValueError("message and key must not be None")
    key_bytes = key16.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("Key must be exactly 16 bytes (UTF-8)")
    msg = message.encode("utf-8")
    if not msg:
        return ""
    k = _key_to_words_le(key_bytes)
    out = bytearray(len(msg))
    block_size = 8
    blocks = (len(msg) + block_size - 1) // block_size
    for i in range(blocks):
        ctr = (nonce + i) & 0xFFFFFFFFFFFFFFFF
        lo = ctr & 0xFFFFFFFF
        hi = (ctr >> 32) & 0xFFFFFFFF
        a, b = _xtea_encrypt_block(lo, hi, k)
        ks = _int_pair_to_bytes_le(a, b)
        off = i * block_size
        remain = min(block_size, len(msg) - off)
        for j in range(remain):
            out[off + j] = msg[off + j] ^ ks[j]
    return _to_hex(bytes(out))

if __name__ == "__main__":
    messages = [
        "",
        "Hello, world!",
        "The quick brown fox jumps over the lazy dog",
        "Sample message with multiple blocks that exceeds eight bytes.",
        "Edge case message 1234567890!@#$%^&*()_+-=[]{}|;:',.<>/?",
    ]
    keys = [
        "0123456789ABCDEF",
        "A1B2C3D4E5F60708",
        "Sixteen byte key",
        "0123456789ABCDE!",
        "Uniq16ByteKey!OK",
    ]
    nonces = [
        0x0123456789ABCDEF,
        0x0F1E2D3C4B5A6978,
        0x1122334455667788,
        0x8877665544332211,
        0xCAFEBABEDEADBEEF,
    ]
    for i in range(5):
        ct = encrypt_message(messages[i], keys[i], nonces[i])
        print(f"Test {i+1} ciphertext (hex): {ct}")