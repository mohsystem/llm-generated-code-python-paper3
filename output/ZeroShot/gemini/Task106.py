# The 'cryptography' library is required. Install it using:
# pip install cryptography
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537

def generate_keys():
    """
    Generates a new RSA private and public key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(data: str, public_key) -> bytes:
    """
    Encrypts data using the public key.
    Note: RSA can only encrypt data smaller than the key size minus padding.
    For larger data, use hybrid encryption (e.g., AES-GCM with an RSA-encrypted key).
    """
    encrypted_data = public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt(encrypted_data: bytes, private_key) -> str:
    """
    Decrypts data using the private key.
    """
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode('utf-8')

def main():
    """Main function to run test cases."""
    try:
        private_key, public_key = generate_keys()

        test_cases = [
            "This is a test message.",
            "RSA is a public-key cryptosystem.",
            "Security is important.",
            "12345!@#$%^&*()",
            "A short message. Real-world applications use RSA to encrypt a symmetric key, not the data itself."
        ]

        for i, original_data in enumerate(test_cases):
            print(f"--- Test Case {i + 1} ---")
            print(f"Original: {original_data}")

            encrypted_data = encrypt(original_data, public_key)
            # Use Base64 for a printable representation of the encrypted bytes
            print(f"Encrypted (Base64): {base64.b64encode(encrypted_data).decode('utf-8')}")

            decrypted_data = decrypt(encrypted_data, private_key)
            print(f"Decrypted: {decrypted_data}")

            print(f"Status: {'SUCCESS' if original_data == decrypted_data else 'FAILURE'}")
            print()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()