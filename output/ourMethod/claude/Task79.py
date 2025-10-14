
import secrets
import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"ENC1"
VERSION = 1
SALT_LENGTH = 16
IV_LENGTH = 12
TAG_LENGTH = 16
ITERATIONS = 210000


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from passphrase using PBKDF2-HMAC-SHA256."""
    if not passphrase or len(passphrase) < 8:
        raise ValueError("Passphrase must be at least 8 characters")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    return kdf.derive(passphrase.encode('utf-8'))


def encrypt(message: str, passphrase: str) -> bytes:
    """Encrypt a message using AES-256-GCM with a passphrase."""
    if not message or message is None:
        if message != "":
            raise ValueError("Message cannot be None")

    if not passphrase or passphrase is None:
        raise ValueError("Passphrase cannot be None or empty")

    if len(passphrase) < 8:
        raise ValueError("Passphrase must be at least 8 characters")

    salt = secrets.token_bytes(SALT_LENGTH)
    iv = secrets.token_bytes(IV_LENGTH)

    key = derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    plaintext = message.encode('utf-8')
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    encrypted_data = MAGIC + bytes([VERSION]) + salt + iv + ciphertext

    return encrypted_data


def decrypt(encrypted_data: bytes, passphrase: str) -> str:
    """Decrypt data encrypted with AES-256-GCM."""
    if not encrypted_data or encrypted_data is None:
        raise ValueError("Encrypted data cannot be None or empty")

    if not passphrase or passphrase is None:
        raise ValueError("Passphrase cannot be None or empty")

    offset = 0

    magic = encrypted_data[offset:offset + 4]
    offset += 4
    if magic != MAGIC:
        raise ValueError("Invalid file format")

    version = encrypted_data[offset]
    offset += 1
    if version != VERSION:
        raise ValueError("Unsupported version")

    salt = encrypted_data[offset:offset + SALT_LENGTH]
    offset += SALT_LENGTH

    iv = encrypted_data[offset:offset + IV_LENGTH]
    offset += IV_LENGTH

    ciphertext = encrypted_data[offset:]

    key = derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)

    return plaintext.decode('utf-8')

def main():
    print("Test Case 1: Basic encryption/decryption")
    message1 = "Hello, World!"
    passphrase1 = "mySecurePassword123"
    encrypted1 = encrypt(message1, passphrase1)
    decrypted1 = decrypt(encrypted1, passphrase1)
    print(f"Original: {message1}")
    print(f"Decrypted: {decrypted1}")
    print(f"Match: {message1 == decrypted1}")
    print()

    print("Test Case 2: Long message")
    message2 = (
        "This is a much longer message that contains multiple sentences. "
        "It should be encrypted and decrypted successfully."
    )
    passphrase2 = "anotherSecurePass456"
    encrypted2 = encrypt(message2, passphrase2)
    decrypted2 = decrypt(encrypted2, passphrase2)
    print(f"Original: {message2}")
    print(f"Decrypted: {decrypted2}")
    print(f"Match: {message2 == decrypted2}")
    print()

    print("Test Case 3: Special characters")
    message3 = "Special chars: @#$%^&*()_+-={}[]|:;<>?,./\\\""
    passphrase3 = "specialCharsPass789"
    encrypted3 = encrypt(message3, passphrase3)
    decrypted3 = decrypt(encrypted3, passphrase3)
    print(f"Original: {message3}")
    print(f"Decrypted: {decrypted3}")
    print(f"Match: {message3 == decrypted3}")
    print()

    print("Test Case 4: Empty string")
    message4 = ""
    passphrase4 = "emptyMessagePass000"
    encrypted4 = encrypt(message4, passphrase4)
    decrypted4 = decrypt(encrypted4, passphrase4)
    print(f"Original: '{message4}'")
    print(f"Decrypted: '{decrypted4}'")
    print(f"Match: {message4 == decrypted4}")
    print()

    print("Test Case 5: Wrong passphrase (should fail)")
    message5 = "Secret message"
    passphrase5 = "correctPassphrase"
    wrong_passphrase = "wrongPassphrase123"
    encrypted5 = encrypt(message5, passphrase5)
    try:
        decrypted5 = decrypt(encrypted5, wrong_passphrase)
        print("ERROR: Should have failed with wrong passphrase")
    except Exception as e:
        print(f"Correctly failed with wrong passphrase: {type(e).__name__}")


if __name__ == "__main__":
    main()
