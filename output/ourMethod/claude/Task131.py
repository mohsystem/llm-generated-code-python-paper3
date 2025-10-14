
import struct
import os
import hashlib
import pickle
from typing import Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from dataclasses import dataclass
import time

MAGIC = b"ENC1"
VERSION = 1
SALT_SIZE = 16
IV_SIZE = 12
TAG_SIZE = 16
MAX_DATA_SIZE = 1024 * 1024  # 1MB limit


@dataclass
class SecureData:
    data: str
    timestamp: float
    
    def __post_init__(self) -> None:
        if not isinstance(self.data, str) or len(self.data) > 10000:
            raise ValueError("Invalid data")


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> type:
        if module == "__main__" and name == "SecureData":
            return SecureData
        raise pickle.UnpicklingError(f"Unauthorized class: {module}.{name}")


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 8:
        raise ValueError("Invalid passphrase")
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode('utf-8'))


def serialize_data(data: SecureData, passphrase: str) -> bytes:
    if not isinstance(data, SecureData) or not isinstance(passphrase, str):
        raise ValueError("Invalid input")
    if len(passphrase) < 8:
        raise ValueError("Passphrase too short")
    
    output = bytearray()
    output.extend(MAGIC)
    output.append(VERSION)
    
    salt = os.urandom(SALT_SIZE)
    output.extend(salt)
    
    key = derive_key(passphrase, salt)
    iv = os.urandom(IV_SIZE)
    output.extend(iv)
    
    plaintext = pickle.dumps(data)
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    output.extend(ciphertext)
    
    return bytes(output)


def deserialize_data(encrypted_data: bytes, passphrase: str) -> SecureData:
    if not isinstance(encrypted_data, bytes) or not isinstance(passphrase, str):
        raise ValueError("Invalid input")
    if len(passphrase) < 8:
        raise ValueError("Passphrase too short")
    if len(encrypted_data) > MAX_DATA_SIZE:
        raise ValueError("Data too large")
    
    min_size = len(MAGIC) + 1 + SALT_SIZE + IV_SIZE + TAG_SIZE
    if len(encrypted_data) < min_size:
        raise ValueError("Data too small")
    
    offset = 0
    
    magic = encrypted_data[offset:offset + len(MAGIC)]
    if magic != MAGIC:
        raise ValueError("Invalid magic")
    offset += len(MAGIC)
    
    version = encrypted_data[offset]
    if version != VERSION:
        raise ValueError("Invalid version")
    offset += 1
    
    salt = encrypted_data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    
    iv = encrypted_data[offset:offset + IV_SIZE]
    offset += IV_SIZE
    
    ciphertext = encrypted_data[offset:]
    
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    
    import io
    obj = RestrictedUnpickler(io.BytesIO(plaintext)).load()
    
    if not isinstance(obj, SecureData):
        raise ValueError("Invalid object type")
    
    return obj


def main() -> None:
    print("Test Case 1: Basic serialization/deserialization")
    data1 = SecureData("Hello World", time.time())
    encrypted1 = serialize_data(data1, "strongpassphrase123")
    decrypted1 = deserialize_data(encrypted1, "strongpassphrase123")
    print(f"Original: {data1}")
    print(f"Decrypted: {decrypted1}")
    print(f"Match: {data1.data == decrypted1.data}")
    print()
    
    print("Test Case 2: Different data")
    data2 = SecureData("Sensitive information 12345", time.time())
    encrypted2 = serialize_data(data2, "anotherpassword456")
    decrypted2 = deserialize_data(encrypted2, "anotherpassword456")
    print(f"Original: {data2}")
    print(f"Decrypted: {decrypted2}")
    print(f"Match: {data2.data == decrypted2.data}")
    print()
    
    print("Test Case 3: Wrong passphrase")
    try:
        data3 = SecureData("Test data", time.time())
        encrypted3 = serialize_data(data3, "correctpass123")
        deserialize_data(encrypted3, "wrongpass123")
        print("ERROR: Should have thrown exception")
    except Exception as e:
        print(f"Correctly rejected wrong passphrase: {type(e).__name__}")
    print()
    
    print("Test Case 4: Corrupted data")
    try:
        data4 = SecureData("Test data", time.time())
        encrypted4 = bytearray(serialize_data(data4, "mypassword789"))
        encrypted4[-1] ^= 0xFF
        deserialize_data(bytes(encrypted4), "mypassword789")
        print("ERROR: Should have thrown exception")
    except Exception as e:
        print(f"Correctly rejected corrupted data: {type(e).__name__}")
    print()
    
    print("Test Case 5: Empty string")
    data5 = SecureData("", time.time())
    encrypted5 = serialize_data(data5, "emptytest123")
    decrypted5 = deserialize_data(encrypted5, "emptytest123")
    print(f"Original: {data5}")
    print(f"Decrypted: {decrypted5}")
    print(f"Match: {data5.data == decrypted5.data}")


if __name__ == "__main__":
    main()
