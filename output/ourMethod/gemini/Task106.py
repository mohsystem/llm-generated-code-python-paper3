import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair():
    """Generates an RSA private and public key pair (2048 bits)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(plain_text: str, public_key) -> bytes:
    """Encrypts a plaintext string using the public key with OAEP padding."""
    # Rule #8: Always incorporate OAEP when using the RSA algorithm
    cipher_text = public_key.encrypt(
        plain_text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

def decrypt(cipher_text: bytes, private_key) -> str:
    """Decrypts a ciphertext using the private key with OAEP padding."""
    plain_text_bytes = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text_bytes.decode('utf-8')

def main():
    """Main function to run test cases."""
    private_key, public_key = generate_rsa_key_pair()

    test_cases = [
        "This is a test message.",
        "RSA with OAEP padding is secure.",
        "Another message for testing purposes.",
        "Short",
        "A much longer message to see how the encryption handles different lengths of input data."
    ]

    for i, original_message in enumerate(test_cases, 1):
        print(f"--- Test Case {i} ---")
        print(f"Original: {original_message}")

        try:
            encrypted = encrypt(original_message, public_key)
            print(f"Encrypted (Base64): {base64.b64encode(encrypted).decode('utf-8')}")

            decrypted = decrypt(encrypted, private_key)
            print(f"Decrypted: {decrypted}")

            if original_message == decrypted:
                print("Status: SUCCESS")
            else:
                print("Status: FAILED")
        except Exception as e:
            print(f"An error occurred: {e}")
            print("Status: FAILED")
        
        print()

if __name__ == "__main__":
    main()