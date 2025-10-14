# NOTE: This code requires the 'cryptography' library.
# Install it using: pip install cryptography

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import List

def generate_openssh_private_key(key_size: int) -> str:
    """
    Generates an RSA private key and exports it in the OpenSSH format.

    Args:
        key_size: The key size in bits. Must be 2048 or greater.

    Returns:
        The RSA private key as a string in OpenSSH format.
    """
    if key_size < 2048:
        raise ValueError("Key size must be at least 2048 bits.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    openssh_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )

    return openssh_pem.decode('utf-8')

def main() -> None:
    """Main function with 5 test cases."""
    key_sizes: List[int] = [2048, 2048, 3072, 4096, 4096]
    for i, size in enumerate(key_sizes):
        try:
            print(f"--- Test Case {i + 1} (Key Size: {size}) ---")
            private_key = generate_openssh_private_key(size)
            print(private_key)
        except ValueError as e:
            print(f"Error generating key for size {size}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()