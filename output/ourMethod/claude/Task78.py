
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import struct
from typing import List


def generate_and_export_rsa_key() -> str:
    """Generate RSA private key and export in OpenSSH format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    openssh_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return openssh_key.decode('utf-8')


def main() -> None:
    """Run test cases for RSA key generation."""
    for i in range(1, 6):
        print(f"Test Case {i}:")
        try:
            private_key = generate_and_export_rsa_key()
            print(private_key[:200] + "...")
            print("Key generated successfully\\n")
        except Exception as e:
            print(f"Error: {e}\\n")


if __name__ == "__main__":
    main()
