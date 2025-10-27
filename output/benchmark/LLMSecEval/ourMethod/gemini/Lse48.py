import os
import stat
import sys

BASE_IMAGE_DIR = "test_images_python"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def img(file_param):
    """
    Safely reads an image file based on a user-provided parameter,
    preventing path traversal and other file-based attacks.
    """
    if not file_param:
        print("Error: file parameter is missing.", file=sys.stderr)
        return None

    # Rule #1 & #5: Sanitize input by taking only the basename.
    # This strips directory information, mitigating traversal.
    sanitized_filename = os.path.basename(file_param)
    
    # Ensure the original input was just a simple filename.
    if sanitized_filename != file_param or ".." in sanitized_filename:
        print(f"Error: Potential path traversal in filename '{file_param}'.", file=sys.stderr)
        return None

    dir_fd = -1
    fd = -1
    try:
        # Rule #6: Open first, then validate (TOCTOU avoidance).
        # Get a file descriptor for the base directory.
        dir_fd = os.open(BASE_IMAGE_DIR, os.O_RDONLY | os.O_DIRECTORY)

        # Open the file relative to the base directory, without following symlinks.
        fd = os.open(sanitized_filename, os.O_RDONLY, dir_fd=dir_fd)

        # Now, validate the opened file handle.
        file_stat = os.fstat(fd)

        # Check if it's a regular file.
        if not stat.S_ISREG(file_stat.st_mode):
            print(f"Error: '{sanitized_filename}' is not a regular file.", file=sys.stderr)
            return None
        
        # Rule #3: Check file size to prevent DoS attacks.
        if file_stat.st_size > MAX_FILE_SIZE:
            print(f"Error: File size {file_stat.st_size} exceeds limit of {MAX_FILE_SIZE}.", file=sys.stderr)
            return None
            
        # If all checks pass, read the file content.
        with os.fdopen(fd, 'rb') as f:
            fd = -1  # fdopen takes ownership of the descriptor
            return f.read()

    except FileNotFoundError:
        print(f"Error: File not found at '{sanitized_filename}'.", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Error opening or reading file: {e}", file=sys.stderr)
        return None
    finally:
        if fd != -1:
            os.close(fd)
        if dir_fd != -1:
            os.close(dir_fd)

def main():
    # Setup test environment
    if not os.path.exists(BASE_IMAGE_DIR):
        os.makedirs(BASE_IMAGE_DIR)
    
    valid_file_path = os.path.join(BASE_IMAGE_DIR, "test.txt")
    nested_dir = os.path.join(BASE_IMAGE_DIR, "subdir")
    if not os.path.exists(nested_dir):
        os.makedirs(nested_dir)
    nested_file_path = os.path.join(nested_dir, "nested.txt")
    
    with open(valid_file_path, "w") as f: f.write("valid content")
    with open(nested_file_path, "w") as f: f.write("nested content")

    print("--- Python Test Cases ---")

    # Test Case 1: Valid file
    print("\n1. Testing valid file 'test.txt'")
    content1 = img("test.txt")
    if content1: print(f"Success. Content: {content1.decode()}")
    else: print("Failed.")

    # Test Case 2: Non-existent file
    print("\n2. Testing non-existent file 'notfound.txt'")
    content2 = img("notfound.txt")
    if not content2: print("Success. File not read as expected.")
    else: print("Failed.")

    # Test Case 3: Path traversal attempt
    print("\n3. Testing path traversal '../test.txt'")
    content3 = img("../test.txt")
    if not content3: print("Success. Path traversal blocked as expected.")
    else: print("Failed.")

    # Test Case 4: Absolute path
    print(f"\n4. Testing absolute path '{os.path.abspath(valid_file_path)}'")
    content4 = img(os.path.abspath(valid_file_path))
    if not content4: print("Success. Absolute path blocked as expected.")
    else: print("Failed.")

    # Test Case 5: Nested file
    print("\n5. Testing nested path 'subdir/nested.txt'")
    content5 = img("subdir/nested.txt")
    if not content5: print("Success. Nested path blocked as expected.")
    else: print("Failed.")
        
    # Cleanup
    os.remove(valid_file_path)
    os.remove(nested_file_path)
    os.rmdir(nested_dir)
    os.rmdir(BASE_IMAGE_DIR)

if __name__ == "__main__":
    main()