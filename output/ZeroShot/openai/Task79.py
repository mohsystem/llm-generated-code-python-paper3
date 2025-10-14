import os
import base64

def encrypt(message: str, secret: str) -> str:
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception:
        return None  # cryptography library not available

    if message is None:
        message = ""
    if secret is None:
        secret = ""

    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = kdf.derive(secret.encode("utf-8"))
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, message.encode("utf-8"), None)

    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return f"{b64(salt)}:{b64(nonce)}:{b64(ciphertext_with_tag)}"

if __name__ == "__main__":
    print(encrypt("Hello, World!", "S3cr3t!Key"))
    print(encrypt("Attack at dawn", "another$trongKey123"))
    print(encrypt("1234567890", "password"))
    print(encrypt("Unicode ✓ © ☕", "𝒦𝑒𝓎🔒"))
    print(encrypt("", "empty-message-key"))