
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import struct
from typing import Tuple

MAGIC = b"ENC1"
VERSION = 1
SALT_LENGTH = 16
GCM_IV_LENGTH = 12
GCM_TAG_LENGTH = 16
AES_KEY_SIZE = 32
RSA_KEY_SIZE = 2048


def generate_rsa_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate RSA key pair with 2048-bit key size."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_with_rsa(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt data using RSA with OAEP padding."""
    if not data:
        raise ValueError("Data cannot be empty")
    if public_key is None:
        raise ValueError("Public key cannot be None")
    
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decrypt_with_rsa(encrypted_data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt data using RSA with OAEP padding."""
    if not encrypted_data:
        raise ValueError("Encrypted data cannot be empty")
    if private_key is None:
        raise ValueError("Private key cannot be None")
    
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


def hybrid_encrypt(plaintext: str, rsa_public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt plaintext using hybrid encryption (AES-GCM + RSA-OAEP)."""
    if not plaintext:
        raise ValueError("Plaintext cannot be empty")
    if rsa_public_key is None:
        raise ValueError("RSA public key cannot be None")
    
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(GCM_IV_LENGTH)
    aes_key = os.urandom(AES_KEY_SIZE)
    
    aesgcm = AESGCM(aes_key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)
    
    encrypted_aes_key = encrypt_with_rsa(aes_key, rsa_public_key)
    
    encrypted_key_length = len(encrypted_aes_key)
    
    result = bytearray()
    result.extend(MAGIC)
    result.append(VERSION)
    result.extend(salt)
    result.extend(iv)
    result.extend(struct.pack('>I', encrypted_key_length))
    result.extend(encrypted_aes_key)
    result.extend(ciphertext)
    
    return bytes(result)


def hybrid_decrypt(encrypted_data: bytes, rsa_private_key: rsa.RSAPrivateKey) -> str:
    """Decrypt data using hybrid decryption (AES-GCM + RSA-OAEP)."""
    min_length = len(MAGIC) + 1 + SALT_LENGTH + GCM_IV_LENGTH + 4
    if not encrypted_data or len(encrypted_data) < min_length:
        raise ValueError("Invalid encrypted data format")
    if rsa_private_key is None:
        raise ValueError("RSA private key cannot be None")
    
    offset = 0
    
    magic = encrypted_data[offset:offset + len(MAGIC)]
    offset += len(MAGIC)
    if magic != MAGIC:
        raise ValueError("Invalid magic number")
    
    version = encrypted_data[offset]
    offset += 1
    if version != VERSION:
        raise ValueError("Unsupported version")
    
    salt = encrypted_data[offset:offset + SALT_LENGTH]
    offset += SALT_LENGTH
    
    iv = encrypted_data[offset:offset + GCM_IV_LENGTH]
    offset += GCM_IV_LENGTH
    
    encrypted_key_length = struct.unpack('>I', encrypted_data[offset:offset + 4])[0]
    offset += 4
    
    if encrypted_key_length <= 0 or encrypted_key_length > 512:
        raise ValueError("Invalid encrypted key length")
    
    encrypted_aes_key = encrypted_data[offset:offset + encrypted_key_length]
    offset += encrypted_key_length
    
    ciphertext = encrypted_data[offset:]
    
    aes_key = decrypt_with_rsa(encrypted_aes_key, rsa_private_key)
    
    aesgcm = AESGCM(aes_key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext, None)
    
    return plaintext_bytes.decode('utf-8')


def main() -> None:
    print("RSA Encryption/Decryption with Hybrid Mode Test Cases:\\n")
    
    private_key, public_key = generate_rsa_key_pair()
    
    test_cases = [
        "Hello, World!",
        "This is a test message for RSA encryption.",
        "Sensitive data: 123456789",
        "AES-256-GCM with RSA-OAEP provides strong security.",
        "Test case #5 with special characters: !@#$%^&*()"
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Original: {test_case}")
        
        encrypted = hybrid_encrypt(test_case, public_key)
        print(f"Encrypted (length): {len(encrypted)} bytes")
        
        decrypted = hybrid_decrypt(encrypted, private_key)
        print(f"Decrypted: {decrypted}")
        print(f"Match: {test_case == decrypted}")
        print()


if __name__ == "__main__":
    main()
