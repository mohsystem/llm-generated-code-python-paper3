import tempfile
import secrets
import string
import os

def create_temp_file_with_unicode_string():
    """
    Creates a temporary file using UTF-8 encoding, creates a random string,
    converts the string into Unicode escape sequences, writes the results
    to the file, and returns the path of the temporary file.
    """
    fd = -1
    path = ""
    try:
        # 1. Create a temporary file securely using mkstemp.
        # This is generally safer against race conditions than other methods.
        fd, path = tempfile.mkstemp(suffix=".txt", text=True)

        # 2. Create a random string using the cryptographically secure 'secrets' module.
        alphabet = string.ascii_letters + string.digits
        random_string = ''.join(secrets.choice(alphabet) for _ in range(20))

        # 3. Convert the string to its Unicode escape sequence representation.
        unicode_escaped_string = ''.join(f'\\u{ord(c):04x}' for c in random_string)

        # 4. Write the Unicode string to the file using UTF-8 encoding.
        # Use os.fdopen with a 'with' statement to properly manage the file descriptor.
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(unicode_escaped_string)
        
        # fd is now closed by the 'with' statement.
        fd = -1

        # 5. Return the path of the temporary file.
        return path
    except Exception as e:
        # Clean up in case of an error during processing.
        if fd != -1:
            os.close(fd)
        if path and os.path.exists(path):
            os.remove(path)
        raise e

def main():
    print("Running 5 test cases for Python...")
    for i in range(1, 6):
        file_path = None
        try:
            file_path = create_temp_file_with_unicode_string()
            print(f"Test case {i}: Success.")
            print(f"  - File created at: {file_path}")

            # For verification, read the content back
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            print(f"  - File content: {content}")

        except Exception as e:
            print(f"Test case {i}: Failed to create temp file. Error: {e}")
        finally:
            # Clean up the created file
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"  - Cleaned up file: {file_path}")
                except OSError as e:
                    print(f"  - Error cleaning up file {file_path}: {e}")
        print("---------------------------------")


if __name__ == "__main__":
    main()