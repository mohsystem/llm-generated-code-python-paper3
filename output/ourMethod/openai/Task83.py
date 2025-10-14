from __future__ import annotations

import secrets
import sys
from typing import ByteString

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MAGIC = b"ECBC"
VERSION = bytes([1])
SALT_LEN = 16
IV_LEN = 16
ENC_KEY_LEN = 32  # AES-256
MAC_KEY_LEN = 32  # HMAC-SHA256
HMAC_LEN = 32
MAX_PLAINTEXT = 1 << 20  # 1 MiB


def encrypt_key_aes_cbc_etm(key_to_encrypt: ByteString, master_key: ByteString) -> bytes:
    if key_to_encrypt is None or master_key is None:
        raise ValueError("Inputs must not be None.")
    if len(key_to_encrypt) == 0 or len(key_to_encrypt) > MAX_PLAINTEXT:
        raise ValueError("Plaintext length out of allowed range.")
    if len(master_key) < 16:
        raise ValueError("Master key must be at least 16 bytes.")

    salt = secrets.token_bytes(SALT_LEN)
    iv = secrets.token_bytes(IV_LEN)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=ENC_KEY_LEN + MAC_KEY_LEN,
        salt=salt,
        info=b"AES-CBC-ETM",
    )
    okm = hkdf.derive(bytes(master_key))
    enc_key = okm[:ENC_KEY_LEN]
    mac_key = okm[ENC_KEY_LEN:ENC_KEY_LEN + MAC_KEY_LEN]

    padder = padding.PKCS7(128).padder()
    padded = padder.update(bytes(key_to_encrypt)) + padder.finalize()

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(MAGIC)
    h.update(VERSION)
    h.update(salt)
    h.update(iv)
    h.update(ciphertext)
    tag = h.finalize()

    out = MAGIC + VERSION + salt + iv + ciphertext + tag

    # Best-effort overwrite of sensitive variables
    enc_key = b"\x00" * len(enc_key)
    mac_key = b"\x00" * len(mac_key)

    return out


def _sha256_hex(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    d = digest.finalize()
    return "".join(f"{b:02x}" for b in d)


def main() -> None:
    try:
        for i in range(1, 6):
            master_key = secrets.token_bytes(32)
            key_len = 8 * i
            key_to_encrypt = secrets.token_bytes(key_len)
            enc = encrypt_key_aes_cbc_etm(key_to_encrypt, master_key)
            print(f"Test {i}: outLen={len(enc)}, sha256={_sha256_hex(enc)}")
    except Exception as e:
        print(f"Error during tests: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()