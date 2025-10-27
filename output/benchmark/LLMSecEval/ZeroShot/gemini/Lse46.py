import os
import sys

def img(name: str):
    """
    Securely retrieves an image file from a designated 'images' directory.
    This function simulates a web endpoint handler for a URL like /img?name=...
    It prevents path traversal attacks by validating the filename and ensuring
    the resolved file path is within the intended directory.

    Args:
        name: The name of the file requested from the 'images' directory.

    Returns:
        A bytes object containing the file's content, or None if the file is
        not found or if a security violation is detected.
    """
    # 1. Basic validation: reject null, empty, or names containing path separators.
    if not name or '..' in name or '/' in name or '\\' in name:
        print(f"Error: Invalid characters or path traversal attempt in filename '{name}'.", file=sys.stderr)
        return None

    try:
        # 2. Define the secure base directory.
        base_dir = os.path.abspath("images")
        if not os.path.isdir(base_dir):
            print(f"Error: Base 'images' directory does not exist.", file=sys.stderr)
            return None

        # 3. Construct the full path and normalize it.
        # os.path.join on its own is not safe. The real security check is below.
        requested_path = os.path.abspath(os.path.join(base_dir, name))

        # 4. Security Check: Ensure the resolved path is still within the base directory.
        # This is the crucial step to prevent path traversal.
        if not requested_path.startswith(base_dir + os.sep):
            print(f"Security Error: Path traversal detected for filename '{name}'.", file=sys.stderr)
            return None

        # 5. Check if the file exists and is a regular file.
        if os.path.exists(requested_path) and os.path.isfile(requested_path):
            with open(requested_path, 'rb') as f:
                return f.read()
        else:
            print(f"Error: File not found or is not a regular file: {requested_path}", file=sys.stderr)
            return None

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None

def main():
    """ Main function with test cases """
    # Setup: Create a dummy directory and files for testing
    image_dir = "images"
    valid_image_path = os.path.join(image_dir, "test.jpg")
    secret_file_path = "secret.txt"

    try:
        os.makedirs(image_dir, exist_ok=True)
        with open(valid_image_path, "w") as f:
            f.write("jpeg_data")
        with open(secret_file_path, "w") as f:
            f.write("secret_data")
        print("Test environment created.")
    except IOError as e:
        print(f"Failed to set up test environment: {e}", file=sys.stderr)
        return

    print("\n--- Running Test Cases ---")

    test_cases = [
        "test.jpg",                     # 1. Valid case
        "../secret.txt",                # 2. Path traversal
        "nonexistent.png",              # 3. File not found
        "test.jpg/../test.jpg",         # 4. More complex invalid name (will fail initial check)
        "../../../../etc/passwd"        # 5. Classic path traversal attack
    ]

    for i, case in enumerate(test_cases):
        print(f"\nTest Case {i + 1}: Requesting '{case}'")
        result = img(case)
        if result:
            print(f"Success: Returned {len(result)} bytes. Content: {result.decode().strip()}")
        else:
            print("Failure: Request denied as expected.")

    # Teardown: Clean up the created files and directory
    try:
        os.remove(valid_image_path)
        os.remove(secret_file_path)
        os.rmdir(image_dir)
        print("\n--- Test environment cleaned up. ---")
    except IOError as e:
        print(f"Failed to clean up test environment: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()