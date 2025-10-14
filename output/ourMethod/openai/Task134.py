from __future__ import annotations
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import secrets
import hmac

MAGIC = b"ENC1"
VERSION = bytes([1])
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
PBKDF2_ITERS = 210_000
KEY_LEN = 32  # 256-bit


def derive_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
    if not isinstance(passphrase, str) or not isinstance(salt, (bytes, bytearray)):
        return b""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: bytes, passphrase: str) -> Optional[bytes]:
    if not isinstance(plaintext, (bytes, bytearray)) or not isinstance(passphrase, str):
        return None
    salt = secrets.token_bytes(SALT_LEN)
    iv = secrets.token_bytes(IV_LEN)
    key = derive_key(passphrase, salt, PBKDF2_ITERS)
    if not key or len(key) != KEY_LEN:
        return None
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, bytes(plaintext), None)
    if len(ct_with_tag) < TAG_LEN:
        return None
    ct = ct_with_tag[:-TAG_LEN]
    tag = ct_with_tag[-TAG_LEN:]
    out = MAGIC + VERSION + salt + iv + ct + tag
    return out


def decrypt(data: bytes, passphrase: str) -> Optional[bytes]:
    if not isinstance(data, (bytes, bytearray)) or not isinstance(passphrase, str):
        return None
    if len(data) < len(MAGIC) + 1 + SALT_LEN + IV_LEN + TAG_LEN:
        return None
    if data[:4] != MAGIC:
        return None
    if data[4:5] != VERSION:
        return None
    salt = data[5:5 + SALT_LEN]
    iv = data[5 + SALT_LEN:5 + SALT_LEN + IV_LEN]
    ct_and_tag = data[5 + SALT_LEN + IV_LEN:]
    if len(ct_and_tag) < TAG_LEN:
        return None
    ct = ct_and_tag[:-TAG_LEN]
    tag = ct_and_tag[-TAG_LEN:]
    key = derive_key(passphrase, salt, PBKDF2_ITERS)
    if not key or len(key) != KEY_LEN:
        return None
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(iv, ct + tag, None)
        return pt
    except Exception:
        return None


def generate_rsa_keypair(bits: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    return priv, pub


def rsa_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> Optional[bytes]:
    try:
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        return None


def rsa_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> Optional[bytes]:
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        return None


def const_time_equals(a: bytes, b: bytes) -> bool:
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False
    return hmac.compare_digest(a, b)


def _run_tests() -> None:
    all_ok = True

    # Test 1: AES-GCM roundtrip
    msg1 = b"Secret message 1"
    pw1 = "correct horse battery staple"
    enc1 = encrypt(msg1, pw1)
    dec1 = decrypt(enc1, pw1) if enc1 else None
    t1 = bool(dec1) and const_time_equals(msg1, dec1 or b"")
    print(f"Test1 AES roundtrip: {t1}")
    all_ok &= t1

    # Test 2: AES-GCM wrong passphrase fails
    dec2 = decrypt(enc1, "wrong pass") if enc1 else None
    t2 = dec2 is None
    print(f"Test2 AES wrong passphrase: {t2}")
    all_ok &= t2

    # Test 3: AES-GCM tamper detection
    if enc1 and len(enc1) > 4 + 1 + SALT_LEN + IV_LEN:
        tampered = bytearray(enc1)
        tampered[4 + 1 + SALT_LEN + IV_LEN] ^= 0x01
        dec3 = decrypt(bytes(tampered), pw1)
        t3 = dec3 is None
    else:
        t3 = False
    print(f"Test3 AES tamper detection: {t3}")
    all_ok &= t3

    # Test 4: RSA OAEP roundtrip
    priv, pub = generate_rsa_keypair(2048)
    msg2 = b"RSA secret"
    renc = rsa_encrypt(msg2, pub)
    rdec = rsa_decrypt(renc, priv) if renc else None
    t4 = bool(rdec) and const_time_equals(msg2, rdec or b"")
    print(f"Test4 RSA OAEP roundtrip: {t4}")
    all_ok &= t4

    # Test 5: RSA wrong key fails
    priv2, pub2 = generate_rsa_keypair(2048)
    rdec_wrong = rsa_decrypt(renc, priv2) if renc else None
    t5 = rdec_wrong is None
    print(f"Test5 RSA wrong key fails: {t5}")
    all_ok &= t5

    print(f"All tests passed: {all_ok}")


if __name__ == "__main__":
    _run_tests()