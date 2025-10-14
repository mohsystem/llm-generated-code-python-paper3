from __future__ import annotations
from typing import Tuple, List
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import hmac


def generate_rsa_keypair(bits: int) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    if bits < 2048:
        raise ValueError("RSA key size must be at least 2048 bits")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    return priv, pub


def rsa_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)) or public_key is None:
        raise ValueError("Invalid input")
    ciphertext = public_key.encrypt(
        bytes(plaintext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def rsa_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)) or private_key is None:
        raise ValueError("Invalid input")
    plaintext = private_key.decrypt(
        bytes(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def main() -> None:
    messages: List[str] = [
        "Hello, RSA OAEP!",
        "The quick brown fox jumps over the lazy dog.",
        "RSA with OAEP SHA-256 and MGF1.",
        "Data 1234567890!@#$%^&*()",
        "Unicode: こんにちは世界🌐",
    ]
    priv, pub = generate_rsa_keypair(2048)
    passed = 0
    for idx, msg in enumerate(messages, 1):
        pt = msg.encode("utf-8")
        ct = rsa_encrypt(pt, pub)
        dec = rsa_decrypt(ct, priv)
        ok = hmac.compare_digest(pt, dec)
        if ok:
            passed += 1
        print(f"Test {idx}: {'OK' if ok else 'FAIL'} | Ciphertext(Base64) length={len(b64(ct))}")
    print(f"Passed {passed} of {len(messages)} tests.")


if __name__ == "__main__":
    main()