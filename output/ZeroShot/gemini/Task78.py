# NOTE: This Python code requires the 'cryptography' library.
# Install it using pip:
# pip install cryptography

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Optional

def generate_and_export_rsa_key(key_size: int) -> Optional[str]:
    """
    Generates an RSA private key and exports it in the OpenSSH format.

    Args:
        key_size: The size of the key in bits (e.g., 2048, 4096).

    Returns:
        The RSA private key in OpenSSH PEM format as a string, or None on error.
    """
    if key_size < 2048:
        print(f"Warning: Key size {key_size} is smaller than the recommended 2048 bits.")
    
    try:
        # 1. Generate the private key
        # public_exponent is usually 65537
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # 2. Serialize the key to OpenSSH format
        # The result is in bytes, so we decode it to a string.
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )

        return pem.decode('utf-8')
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def main():
    """Main function with 5 test cases."""
    key_sizes = [2048, 2048, 3072, 4096, 4096]
    for i, size in enumerate(key_sizes):
        print(f"--- Test Case {i + 1} (Key Size: {size}) ---")
        openssh_key = generate_and_export_rsa_key(size)
        if openssh_key:
            print(openssh_key)
        else:
            print("Failed to generate key.")

if __name__ == "__main__":
    main()