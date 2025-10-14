import tempfile
import secrets
import string
import os

def generate_random_string(length: int) -> str:
    """
    Generates a cryptographically secure random alphanumeric string.
    """
    if length <= 0:
        raise ValueError("String length must be positive.")
    alphabet = string.ascii_letters + string.digits
    random_part = ''.join(secrets.choice(alphabet) for _ in range(length))
    # Add a unicode character to ensure it's not just ASCII
    return f"{random_part}-€"

def create_temp_file_with_random_unicode() -> str:
    """
    Creates a secure temporary file, writes a random Unicode string to it 
    (UTF-8 encoded), and returns the file's path. The caller is responsible 
    for deleting the file.
    """
    # 1. Create a temporary file securely.
    # We use delete=False so the file is not removed upon closing,
    # as we need to return its path. 
    # The 'w' mode is for writing text, and encoding='utf-8' handles Unicode.
    try:
        tf = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt', prefix='tempfile_')
        file_path = tf.name
        
        with tf:
            # 2. Create a random string.
            random_content = generate_random_string(32)
            
            # 3. Write the string to the file.
            # Python 3 strings are Unicode. The file's encoding handles the conversion.
            tf.write(random_content)

        # 4. Return the path of the temporary file.
        return file_path
    except IOError as e:
        print(f"An error occurred during file operation: {e}")
        return None

def main():
    """Main function to run test cases."""
    print("Running 5 test cases for Python...")
    created_files = []
    for i in range(5):
        print(f"Test Case {i + 1}: ", end="")
        file_path = create_temp_file_with_random_unicode()
        if file_path:
            print(f"Success. File created at: {file_path}")
            created_files.append(file_path)
            # Optional: verify content
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.endswith("-€"):
                        print("   Content verification successful.")
                    else:
                        print("   Content verification failed.")
            except IOError as e:
                print(f"   Could not read back file for verification: {e}")
        else:
            print("Failed.")

    # Cleanup the created files
    if created_files:
        print("\nCleaning up temporary files...")
        for file_path in created_files:
            try:
                os.remove(file_path)
                print(f"Removed: {file_path}")
            except OSError as e:
                print(f"Error removing {file_path}: {e}")

if __name__ == "__main__":
    main()