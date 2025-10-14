import tempfile
import secrets
import string
import os
import sys

def create_temp_file_with_unicode_string() -> str:
    """
    Creates a temporary file with a random string represented in Unicode code points.

    Returns:
        str: The absolute path to the created temporary file.
    
    Raises:
        IOError: If there is an error during file operations.
    """
    
    file_path = None
    try:
        # 1. Create a random string using a cryptographically secure generator.
        alphabet = string.ascii_letters + string.digits
        random_string = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        # 2. Convert the string into a Unicode representation.
        unicode_representation = ' '.join(f'U+{ord(c):04X}' for c in random_string)

        # 3. Create a temporary file securely.
        # NamedTemporaryFile is used with delete=False so the file persists
        # after closing and its path can be returned. The caller is responsible for cleanup.
        # The 'w' mode opens the file in text mode, and encoding='utf-8' is specified.
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, 
                                         prefix='task88_', suffix='.txt') as temp_file:
            temp_file.write(unicode_representation)
            file_path = temp_file.name
        
        # 4. Return the path of the temporary file.
        return os.path.abspath(file_path)
    except IOError:
        # If file was created but an error occurred later, try to clean up.
        if file_path and os.path.exists(file_path):
             os.remove(file_path)
        # Re-raise the caught exception.
        raise

def main():
    """Main function with test cases."""
    for i in range(5):
        file_path = None
        try:
            file_path = create_temp_file_with_unicode_string()
            print(f"Test Case {i + 1}: Created temp file at: {file_path}")
            # Optional: Read and print content for verification
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                print(f"  File content: {content}")
        except IOError as e:
            print(f"Test Case {i + 1}: An error occurred: {e}", file=sys.stderr)
        finally:
            # Clean up the created file
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
                print(f"  Cleaned up temp file: {file_path}")

if __name__ == "__main__":
    main()