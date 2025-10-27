import os
import base64
import tempfile
import shutil
import sys

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def upload_image(input_base_dir, input_filename, output_base_dir, output_filename):
    """
    Reads an image from a validated path, encodes it in Base64, and writes it to a new file atomically.

    :param input_base_dir: The trusted base directory for input files.
    :param input_filename: The name of the input image file.
    :param output_base_dir: The trusted base directory for output files.
    :param output_filename: The name of the output file.
    :return: True on success, False on failure.
    """
    # Rule #5: Validate paths to prevent traversal
    try:
        real_input_base = os.path.realpath(input_base_dir)
        real_output_base = os.path.realpath(output_base_dir)

        input_path = os.path.realpath(os.path.join(real_input_base, input_filename))
        output_path = os.path.realpath(os.path.join(real_output_base, output_filename))

        if not input_path.startswith(real_input_base):
            print(f"Error: Input path '{input_path}' is outside the allowed directory '{real_input_base}'.", file=sys.stderr)
            return False
        if not output_path.startswith(real_output_base):
            print(f"Error: Output path '{output_path}' is outside the allowed directory '{real_output_base}'.", file=sys.stderr)
            return False
    except Exception as e:
        print(f"Error resolving paths: {e}", file=sys.stderr)
        return False
        
    # Python's os.path.realpath resolves symlinks, so a direct os.open with O_NOFOLLOW is better.
    # Re-construct path without realpath for the open call.
    safe_input_path = os.path.join(input_base_dir, input_filename)

    fd = -1
    try:
        # Rule #6: Open file first (TOCTOU-safe)
        # O_NOFOLLOW prevents opening symbolic links.
        open_flags = os.O_RDONLY
        if hasattr(os, 'O_NOFOLLOW'):
            open_flags |= os.O_NOFOLLOW
        
        fd = os.open(safe_input_path, open_flags)

        # Then validate the handle
        stat_info = os.fstat(fd)
        
        # Check if it's a regular file
        import stat
        if not stat.S_ISREG(stat_info.st_mode):
            print(f"Error: Input '{input_filename}' is not a regular file.", file=sys.stderr)
            return False

        # Rule #3: Check file size
        if stat_info.st_size > MAX_FILE_SIZE:
            print(f"Error: File size {stat_info.st_size} exceeds limit of {MAX_FILE_SIZE} bytes.", file=sys.stderr)
            return False
            
        if stat_info.st_size == 0:
            print(f"Error: Input file is empty.", file=sys.stderr)
            return False

        # Read content from the file descriptor
        with os.fdopen(fd, 'rb') as f:
            file_content = f.read()
        fd = -1 # fdopen took ownership

    except FileNotFoundError:
        print(f"Error: Input file not found: {safe_input_path}", file=sys.stderr)
        return False
    except OSError as e:
        # This will catch O_NOFOLLOW error on symlinks (ELOOP)
        print(f"Error opening or reading input file: {e}", file=sys.stderr)
        return False
    finally:
        if fd != -1:
            os.close(fd)

    # Base64 encode
    encoded_content = base64.b64encode(file_content)

    # Rule #6: Safe and atomic write
    try:
        os.makedirs(output_base_dir, exist_ok=True)
        # Create a temporary file in the same directory
        with tempfile.NamedTemporaryFile(mode='wb', dir=output_base_dir, delete=False, prefix=output_filename, suffix=".tmp") as temp_f:
            temp_path = temp_f.name
            temp_f.write(encoded_content)
        
        # Atomically replace/rename the file
        os.replace(temp_path, output_path)
    except Exception as e:
        print(f"Error writing to output file: {e}", file=sys.stderr)
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return False
    
    return True

def main():
    # Setup test environment
    input_base = "test_images_python"
    output_base = "test_output_python"
    
    if os.path.exists(input_base): shutil.rmtree(input_base)
    if os.path.exists(output_base): shutil.rmtree(output_base)
    
    os.makedirs(input_base)
    os.makedirs(output_base)

    valid_image_path = os.path.join(input_base, "valid_image.jpg")
    large_image_path = os.path.join(input_base, "large_image.jpg")
    symlink_image_path = os.path.join(input_base, "symlink.jpg")

    with open(valid_image_path, "wb") as f:
        f.write(b"\x01\x02\x03\x04\x05")

    with open(large_image_path, "wb") as f:
        f.write(b'\0' * (MAX_FILE_SIZE + 1))

    symlink_supported = True
    if hasattr(os, "symlink"):
        try:
            os.symlink(valid_image_path, symlink_image_path)
        except (OSError, AttributeError, NotImplementedError):
            print("Skipping symlink test: Not supported or permitted on this system.")
            symlink_supported = False
    else:
        symlink_supported = False

    print("--- Running Python Test Cases ---")

    # 1. Valid upload
    print("1. Testing valid upload... ", end="")
    success = upload_image(input_base, "valid_image.jpg", output_base, "encoded.txt")
    print("SUCCESS" if success else "FAILED")
    assert success

    # 2. File too large
    print("2. Testing file too large... ", end="")
    success = upload_image(input_base, "large_image.jpg", output_base, "encoded_large.txt")
    print("SUCCESS (Rejected as expected)" if not success else "FAILED")
    assert not success

    # 3. Symbolic link
    if symlink_supported and hasattr(os, 'O_NOFOLLOW'):
        print("3. Testing symbolic link... ", end="")
        success = upload_image(input_base, "symlink.jpg", output_base, "encoded_symlink.txt")
        print("SUCCESS (Rejected as expected)" if not success else "FAILED")
        assert not success

    # 4. Path traversal
    print("4. Testing path traversal... ", end="")
    success = upload_image(input_base, "../test_traversal.jpg", output_base, "encoded_traversal.txt")
    print("SUCCESS (Rejected as expected)" if not success else "FAILED")
    assert not success

    # 5. Non-existent file
    print("5. Testing non-existent file... ", end="")
    success = upload_image(input_base, "not_real.jpg", output_base, "encoded_not_real.txt")
    print("SUCCESS (Rejected as expected)" if not success else "FAILED")
    assert not success

    # Cleanup
    shutil.rmtree(input_base)
    shutil.rmtree(output_base)
    print("--- Python Tests Complete ---")

if __name__ == "__main__":
    main()