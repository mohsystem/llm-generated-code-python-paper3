import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_key_pair():
    """Generates a 2048-bit RSA private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(message, public_key):
    """Encrypts a message using the RSA public key with OAEP padding."""
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(ciphertext, private_key):
    """Decrypts a message using the RSA private key with OAEP padding."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def main():
    """Main function to run test cases."""
    test_cases = [
        "This is a secret message.",
        "RSA is a public-key cryptosystem.",
        "Security is important.",
        "Test case 4 with numbers 12345.",
        "Final test case with symbols !@#$%"
    ]
    
    print("--- Python RSA Encryption/Decryption ---")

    for i, original_message in enumerate(test_cases):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Original Message: {original_message}")

        try:
            # 1. Generate Key Pair
            private_key, public_key = generate_rsa_key_pair()

            # 2. Encrypt the message
            encrypted_message = encrypt(original_message, public_key)
            encoded_message = base64.b64encode(encrypted_message).decode('utf-8')
            print(f"Encrypted (Base64): {encoded_message}")

            # 3. Decrypt the message
            decrypted_message = decrypt(encrypted_message, private_key)
            print(f"Decrypted Message: {decrypted_message}")

            # Verification
            if original_message != decrypted_message:
                print("Error: Decrypted message does not match original.")

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()