# Note: This code requires the 'cryptography' library.
# Install it using pip: pip install cryptography

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_openssh_private_key(key_size: int) -> str:
    """
    Generates an RSA private key and returns it in the OpenSSH format.

    :param key_size: The size of the key in bits (e.g., 2048, 4096).
    :return: A string containing the RSA private key in OpenSSH format, or None on failure.
    """
    try:
        # Generate the RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Serialize the key to the OpenSSH format (which is a type of PEM encoding)
        # without any encryption.
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )

        return pem.decode('utf-8')
    except Exception as e:
        print(f"An error occurred during key generation: {e}")
        return None

class Task78:
    @staticmethod
    def main():
        """Main function with test cases."""
        print("--- Python RSA OpenSSH Key Generation ---")
        print("Note: Requires the 'cryptography' library.")
        
        for i in range(1, 6):
            print(f"\n--- Test Case {i} (2048 bits) ---")
            private_key = generate_openssh_private_key(2048)
            if private_key:
                print(private_key)
            else:
                print("Key generation failed.")

if __name__ == "__main__":
    Task78.main()