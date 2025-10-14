import os

def process_file(key, input_file_path, output_file_path):
    """
    Encrypts or decrypts a file using a simple XOR cipher with a given key.
    The operation is symmetric; applying it twice restores the original file.
    
    :param key: The secret key for encryption/decryption as a string.
    :param input_file_path: Path to the input file.
    :param output_file_path: Path to the output file.
    """
    if not key:
        print("Error: Key cannot be empty.")
        return

    try:
        key_bytes = key.encode('utf-8')
        key_len = len(key_bytes)
        
        with open(input_file_path, 'rb') as f_in, open(output_file_path, 'wb') as f_out:
            i = 0
            while True:
                # Read the input file in chunks for efficiency
                chunk = f_in.read(1024)
                if not chunk:
                    break
                
                processed_chunk = bytearray()
                for byte in chunk:
                    # XOR each byte with the corresponding key byte
                    processed_chunk.append(byte ^ key_bytes[i % key_len])
                    i += 1
                
                f_out.write(processed_chunk)
                
    except FileNotFoundError:
        print(f"Error: The file '{input_file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def run_test_case(test_id, content, key):
    """Helper function to run a complete test case."""
    plain_file = f"{test_id}_plain.txt"
    encrypted_file = f"{test_id}_encrypted.bin"
    decrypted_file = f"{test_id}_decrypted.txt"
    
    try:
        # 1. Create the original file
        with open(plain_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"\n--- Running Test Case: {test_id} ---")
        print(f"Original content: \"{content}\"")

        # 2. Encrypt
        process_file(key, plain_file, encrypted_file)
        print(f"'{plain_file}' encrypted to '{encrypted_file}' with key '{key}'.")

        # 3. Decrypt
        process_file(key, encrypted_file, decrypted_file)
        print(f"'{encrypted_file}' decrypted to '{decrypted_file}'.")

        # 4. Verify
        with open(decrypted_file, 'r', encoding='utf-8') as f:
            decrypted_content = f.read()
        
        if content == decrypted_content:
            print("SUCCESS: Decrypted content matches original content.")
        else:
            print("FAILURE: Content mismatch!")
            print(f"Decrypted content: \"{decrypted_content}\"")

    except Exception as e:
        print(f"An error occurred during the test case: {e}")
    finally:
        # 5. Cleanup
        for f in [plain_file, encrypted_file, decrypted_file]:
            if os.path.exists(f):
                os.remove(f)

if __name__ == "__main__":
    print("--- Python File Encryption/Decryption Tests ---")

    # Test Case 1: Simple text
    run_test_case("test1", "Hello World!", "KEY1")
    
    # Test Case 2: Different key and text
    run_test_case("test2", "Python XOR Encryption/Decryption.", "SECRET")
    
    # Test Case 3: Longer text to test key wrapping
    run_test_case("test3", "This is a longer piece of text to ensure the key repeats correctly.", "LONGERKEY")

    # Test Case 4: Text with special characters and numbers
    run_test_case("test4", "12345!@#$%^&*()_+", "NUMSYM")

    # Test Case 5: Empty file
    run_test_case("test5", "", "EMPTY")
    
    print("\n--- Python Tests Completed ---")