import sys
from typing import Tuple, Union
import secrets
import hmac as stdlib_hmac

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac as crypto_hmac


MAGIC = b"ENC1"
VERSION = 1
SALT_LEN = 16       # 16-byte unique salt per encryption
IV_LEN = 16         # AES-CBC IV is 16 bytes
TAG_LEN = 16        # 128-bit tag (truncated HMAC-SHA-256)
KDF_ITERS = 210_000
ENC_KEY_LEN = 32    # AES-256
MAC_KEY_LEN = 32    # HMAC-SHA-256 key length
MAX_PLAINTEXT_LEN = 4096  # conservative upper bound for input validation


def _to_bytes(value: Union[str, bytes], name: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"{name} must be str or bytes")


def _derive_keys(passphrase: bytes, salt: bytes = None) -> Tuple[bytes, bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(SALT_LEN)
    if not isinstance(salt, bytes) or len(salt) != SALT_LEN:
        raise ValueError("Invalid salt")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENC_KEY_LEN + MAC_KEY_LEN,
        salt=salt,
        iterations=KDF_ITERS,
    )
    key_material = kdf.derive(passphrase)
    enc_key = key_material[:ENC_KEY_LEN]
    mac_key = key_material[ENC_KEY_LEN:]
    return enc_key, mac_key, salt


def _build_header(salt: bytes, iv: bytes) -> bytes:
    return MAGIC + VERSION.to_bytes(1, "big") + salt + iv


def _parse_header(blob: bytes) -> Tuple[int, bytes, bytes]:
    min_header = len(MAGIC) + 1 + SALT_LEN + IV_LEN
    if len(blob) < min_header + TAG_LEN:
        raise ValueError("Invalid data length")
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("Bad magic")
    version = blob[len(MAGIC)]
    if version != VERSION:
        raise ValueError("Unsupported version")
    offset = len(MAGIC) + 1
    salt = blob[offset : offset + SALT_LEN]
    offset += SALT_LEN
    iv = blob[offset : offset + IV_LEN]
    offset += IV_LEN
    return offset, salt, iv


def encrypt_key_cbc(passphrase: Union[str, bytes], key_to_encrypt: bytes) -> bytes:
    """
    Encrypt a given key using AES-256-CBC with Encrypt-then-MAC (HMAC-SHA-256, truncated to 16 bytes).
    Output format: [magic="ENC1"][version=1][salt(16)][iv(16)][ciphertext][tag(16)]
    """
    p_bytes = _to_bytes(passphrase, "passphrase")
    if not isinstance(key_to_encrypt, (bytes, bytearray)):
        raise TypeError("key_to_encrypt must be bytes-like")
    pt = bytes(key_to_encrypt)
    if len(pt) == 0 or len(pt) > MAX_PLAINTEXT_LEN:
        raise ValueError("Invalid key length")
    enc_key, mac_key, salt = _derive_keys(p_bytes)
    iv = secrets.token_bytes(IV_LEN)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(pt) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    header = _build_header(salt, iv)
    h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
    h.update(header)
    h.update(ciphertext)
    full_tag = h.finalize()
    tag = full_tag[:TAG_LEN]

    return header + ciphertext + tag


def decrypt_key_cbc(passphrase: Union[str, bytes], blob: bytes) -> bytes:
    """
    Decrypt data produced by encrypt_key_cbc. Verifies HMAC tag before decryption.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes-like")
    p_bytes = _to_bytes(passphrase, "passphrase")

    offset, salt, iv = _parse_header(blob)
    if len(blob) < offset + TAG_LEN + 1:
        raise ValueError("Invalid data length")
    tag = blob[-TAG_LEN:]
    ciphertext = blob[offset:-TAG_LEN]
    if len(ciphertext) == 0 or len(ciphertext) % IV_LEN != 0:
        raise ValueError("Invalid ciphertext length")

    enc_key, mac_key, _ = _derive_keys(p_bytes, salt)

    header = _build_header(salt, iv)
    h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
    h.update(header)
    h.update(ciphertext)
    comp_tag_full = h.finalize()
    comp_tag = comp_tag_full[:TAG_LEN]
    if not stdlib_hmac.compare_digest(comp_tag, tag):
        raise ValueError("Authentication failed")

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        pt = unpadder.update(padded) + unpadder.finalize()
    except Exception as exc:
        # Fail closed without leaking details
        raise ValueError("Invalid padding") from exc
    return pt


def _run_tests() -> None:
    tests = []

    # Test 1: 16-byte key
    tests.append((
        "correct horse battery staple",
        bytes([0x01] * 16),
    ))

    # Test 2: 32-byte key
    tests.append((
        "another-passphrase",
        secrets.token_bytes(32),
    ))

    # Test 3: binary key with edge byte values
    tests.append((
        "pässwörd-Üñíçødê",
        bytes([0x00, 0xFF, 0x7F, 0x80, 0x01, 0x02, 0xFE, 0x10, 0x20, 0x30, 0xAA, 0x55, 0xCC, 0x33, 0x99, 0x66]),
    ))

    # Test 4: 64-byte key
    tests.append((
        "S3cure-Passphrase-#4",
        secrets.token_bytes(64),
    ))

    # Test 5: random length key within bounds
    tests.append((
        "fifth case passphrase",
        secrets.token_bytes(57),
    ))

    for idx, (pw, key) in enumerate(tests, start=1):
        blob = encrypt_key_cbc(pw, key)
        recovered = decrypt_key_cbc(pw, blob)
        assert recovered == key, f"Test {idx} failed: recovered key mismatch"
        # Tamper test: flip a bit and ensure auth fails
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        try:
            _ = decrypt_key_cbc(pw, bytes(tampered))
            raise AssertionError(f"Test {idx} failed: tampering not detected")
        except ValueError:
            pass

    print("All tests passed")


if __name__ == "__main__":
    _run_tests()