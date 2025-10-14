# This script requires the 'cryptography' library.
# Install it using: pip install cryptography

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_openssh_private_key(key_size: int) -> str:
    """
    Generates an RSA private key and exports it in the OpenSSH format.
    
    Args:
        key_size: The size of the key in bits (e.g., 2048, 4096).
    
    Returns:
        The RSA private key as a string in OpenSSH PEM format.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize the key to the OpenSSH private key format, unencrypted.
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pem.decode('utf-8')

def main():
    """Main function with test cases."""
    test_key_sizes = [1024, 1024, 2048, 2048, 4096]
    for i, size in enumerate(test_key_sizes):
        print(f"--- Test Case {i + 1}: Generating {size}-bit key ---")
        try:
            # 1024-bit keys are small for modern standards, but fine for testing.
            if size < 2048:
                print(f"(Note: {size}-bit RSA is considered weak for production use.)")
            key = generate_openssh_private_key(size)
            print(key)
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()