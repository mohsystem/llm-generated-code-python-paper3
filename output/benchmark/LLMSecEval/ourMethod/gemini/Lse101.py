import os
import tempfile
import sys

def write_important_config(file_name, content):
    """
    Creates a file with the given name and writes the specified content to it securely.
    This function uses a temporary file and an atomic replace operation to prevent
    race conditions and ensure the file is written completely or not at all.
    """
    temp_fd = -1
    temp_path = None
    dir_fd = -1
    success = False

    try:
        # Create a temporary file in the current directory. mkstemp is secure,
        # creating a file with a unique name and restrictive permissions (0o600 on POSIX).
        temp_fd, temp_path = tempfile.mkstemp(dir='.', prefix=file_name, suffix='.tmp')

        # Write content to the temporary file.
        # os.write works with bytes, so we encode the string.
        encoded_content = content.encode('utf-8')
        bytes_written = os.write(temp_fd, encoded_content)
        if bytes_written != len(encoded_content):
            raise IOError("Failed to write all content to temporary file.")

        # Ensure data is written to the disk.
        os.fsync(temp_fd)
        os.close(temp_fd)
        temp_fd = -1

        # Atomically replace the final file with the temporary file.
        os.replace(temp_path, file_name)
        temp_path_for_cleanup = None  # The file has been moved, don't try to delete it.

        # Sync the parent directory to ensure the rename operation is persisted.
        # O_CLOEXEC is not available on Windows, but getattr provides a safe way to use it.
        dir_fd = os.open('.', os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0))
        os.fsync(dir_fd)
        
        success = True
    except (IOError, OSError) as e:
        sys.stderr.write(f"Error writing to file: {e}\n")
        success = False
    finally:
        # Clean up resources.
        if temp_fd != -1:
            os.close(temp_fd)
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        if dir_fd != -1:
            os.close(dir_fd)
    
    return success

def main():
    """Main function with test cases."""
    file_name = "important_config"
    content = "important_config"
    for i in range(1, 6):
        print(f"Test Case {i}:")
        success = write_important_config(file_name, content)
        if success:
            print(f"Successfully wrote to {file_name}")
            # Optional: verify content
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    read_content = f.read()
                print(f"File content verification: {'PASSED' if content == read_content else 'FAILED'}")
            except IOError as e:
                print(f"Failed to read back file for verification: {e}")
        else:
            print(f"Failed to write to {file_name}")
        print("--------------------")

if __name__ == "__main__":
    main()