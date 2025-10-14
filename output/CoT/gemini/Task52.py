# To run this code, you must install the 'cryptography' library:
# pip install cryptography
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Constants
AES_KEY_BYTES = 32  # 256-bit key
NONCE_BYTES = 12    # 96-bit nonce, as recommended for GCM

def encrypt_file(input_file, output_file, key):
    """
    Encrypts a file using AES-256-GCM.
    :param input_file: Path to the input file.
    :param output_file: Path to the output encrypted file.
    :param key: The 256-bit (32-byte) encryption key.
    :return: True on success, False on failure.
    """
    if len(key) != AES_KEY_BYTES:
        print(f"Error: Invalid key size. Key must be {AES_KEY_BYTES} bytes.")
        return False
    
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(NONCE_BYTES)

        with open(input_file, 'rb') as f_in:
            plaintext = f_in.read()

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Prepend nonce to the ciphertext for use in decryption
        with open(output_file, 'wb') as f_out:
            f_out.write(nonce)
            f_out.write(ciphertext)
            
        return True
    except FileNotFoundError:
        print(f"Error: Input file not found at {input_file}")
        return False
    except Exception as e:
        print(f"An encryption error occurred: {e}")
        return False


def decrypt_file(input_file, output_file, key):
    """
    Decrypts a file using AES-256-GCM.
    :param input_file: Path to the input encrypted file.
    :param output_file: Path to the output decrypted file.
    :param key: The 256-bit (32-byte) decryption key.
    :return: True on success, False on failure.
    """
    if len(key) != AES_KEY_BYTES:
        print(f"Error: Invalid key size. Key must be {AES_KEY_BYTES} bytes.")
        return False

    try:
        with open(input_file, 'rb') as f_in:
            # Read the nonce from the beginning of the file
            nonce = f_in.read(NONCE_BYTES)
            ciphertext = f_in.read()
        
        aesgcm = AESGCM(key)
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        with open(output_file, 'wb') as f_out:
            f_out.write(plaintext)
            
        return True
    except FileNotFoundError:
        print(f"Error: Input file not found at {input_file}")
        return False
    except InvalidTag:
        print("Decryption failed: Incorrect key or tampered data.")
        return False
    except Exception as e:
        print(f"A decryption error occurred: {e}")
        return False

def main():
    """ Main function with test cases """
    # --- Test Setup ---
    ORIGINAL_FILE = "original.txt"
    ENCRYPTED_FILE = "encrypted.bin"
    DECRYPTED_FILE = "decrypted.txt"
    TAMPERED_FILE = "tampered.bin"
    EMPTY_FILE = "empty.txt"
    EMPTY_ENC_FILE = "empty.enc"
    EMPTY_DEC_FILE = "empty.dec"
    NON_EXISTENT_FILE = "non_existent.txt"
    
    # In a real application, derive the key from a password using a KDF
    # or use a secure random key generator.
    correct_key = os.urandom(AES_KEY_BYTES)
    wrong_key = os.urandom(AES_KEY_BYTES)
    
    original_content = b"This is a secret message for testing AES-GCM file encryption."

    # --- Test Case 1: Successful Encryption and Decryption ---
    print("--- Test Case 1: Successful Encryption/Decryption ---")
    with open(ORIGINAL_FILE, 'wb') as f:
        f.write(original_content)
    
    encrypt_success = encrypt_file(ORIGINAL_FILE, ENCRYPTED_FILE, correct_key)
    decrypt_success = decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, correct_key)
    
    with open(DECRYPTED_FILE, 'rb') as f:
        decrypted_content = f.read()

    if encrypt_success and decrypt_success and original_content == decrypted_content:
        print("Test 1 Passed: Content matches after decryption.")
    else:
        print("Test 1 Failed.")
    print("--------------------------------------------------\n")

    # --- Test Case 2: Decryption with Wrong Key ---
    print("--- Test Case 2: Decryption with Wrong Key ---")
    decrypt_wrong_key = decrypt_file(ENCRYPTED_FILE, "decrypted_wrong.txt", wrong_key)
    if not decrypt_wrong_key:
        print("Test 2 Passed: Decryption failed as expected.")
    else:
        print("Test 2 Failed: Decryption succeeded with a wrong key.")
    print("--------------------------------------------------\n")

    # --- Test Case 3: Decryption of Tampered File ---
    print("--- Test Case 3: Decryption of Tampered File ---")
    with open(ENCRYPTED_FILE, 'rb') as f_in:
        tampered_data = bytearray(f_in.read())
    if len(tampered_data) > NONCE_BYTES:
        tampered_data[-1] ^= 1 # Flip a bit in the ciphertext/tag
    with open(TAMPERED_FILE, 'wb') as f_out:
        f_out.write(tampered_data)
        
    decrypt_tampered = decrypt_file(TAMPERED_FILE, "decrypted_tampered.txt", correct_key)
    if not decrypt_tampered:
        print("Test 3 Passed: Decryption of tampered file failed as expected.")
    else:
        print("Test 3 Failed: Decryption of tampered file succeeded.")
    print("--------------------------------------------------\n")

    # --- Test Case 4: Encrypting and Decrypting an Empty File ---
    print("--- Test Case 4: Encrypt/Decrypt Empty File ---")
    with open(EMPTY_FILE, 'wb') as f:
        pass # Create empty file
    encrypt_empty = encrypt_file(EMPTY_FILE, EMPTY_ENC_FILE, correct_key)
    decrypt_empty = decrypt_file(EMPTY_ENC_FILE, EMPTY_DEC_FILE, correct_key)
    
    if encrypt_empty and decrypt_empty and os.path.getsize(EMPTY_DEC_FILE) == 0:
        print("Test 4 Passed: Empty file handled correctly.")
    else:
        print("Test 4 Failed.")
    print("--------------------------------------------------\n")

    # --- Test Case 5: Handling Non-Existent Input File ---
    print("--- Test Case 5: Handling Non-Existent Input File ---")
    encrypt_non_existent = encrypt_file(NON_EXISTENT_FILE, "out.enc", correct_key)
    if not encrypt_non_existent:
        print("Test 5 Passed: Handled non-existent input file correctly.")
    else:
        print("Test 5 Failed.")
    print("--------------------------------------------------\n")

    # --- Cleanup ---
    for f in [ORIGINAL_FILE, ENCRYPTED_FILE, DECRYPTED_FILE, "decrypted_wrong.txt",
              TAMPERED_FILE, "decrypted_tampered.txt", EMPTY_FILE, EMPTY_ENC_FILE,
              EMPTY_DEC_FILE]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == '__main__':
    main()