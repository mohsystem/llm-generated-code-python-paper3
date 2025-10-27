import os
import base64
import re
import sys

# Define a reasonable max file size to prevent DoS attacks (e.g., 5MB)
MAX_FILE_SIZE = 5 * 1024 * 1024
# Whitelist for safe characters in a filename
SAFE_FILENAME_REGEX = re.compile(r'^[a-zA-Z0-9._-]+$')

def upload_image(file_path: str) -> bool:
    """
    Securely handles image upload: validates, reads, base64 encodes, and simulates a secure DB insert.
    """
    print(f"--- Processing: {file_path} ---")
    try:
        # 1. Input Validation: File Existence and Type
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            print("Error: File does not exist or is not a regular file.", file=sys.stderr)
            return False

        # 2. Security: Sanitize Filename
        # Prevent path traversal by only using the base name of the file
        original_filename = os.path.basename(file_path)

        # Validate filename against a strict whitelist
        if not SAFE_FILENAME_REGEX.match(original_filename):
            print("Error: Filename contains invalid characters.", file=sys.stderr)
            return False
        sanitized_filename = original_filename

        # 3. Security: Check File Size
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            print(f"Error: File size ({file_size} bytes) exceeds the limit of {MAX_FILE_SIZE} bytes.", file=sys.stderr)
            return False
        if file_size == 0:
            print("Error: File is empty.", file=sys.stderr)
            return False

        # 4. Read file and convert to Base64
        with open(file_path, 'rb') as f:
            file_bytes = f.read()
        base64_string = base64.b64encode(file_bytes).decode('utf-8')

        # 5. Security: Simulate Secure Database Insertion
        # Using parameterized queries is crucial to prevent SQL Injection.
        # We simulate this by showing the query template and the parameters tuple.
        print("Simulating secure database insert...")
        query_template = "INSERT INTO images (name, data) VALUES (%s, %s);"
        params = (sanitized_filename, base64_string)
        print(f"  Query Template: {query_template}")
        print(f"  Binding Param 1 (name): {params[0]}")
        truncated_base64 = params[1][:40] + '...' if len(params[1]) > 40 else params[1]
        print(f"  Binding Param 2 (data): {truncated_base64}")
        print("  Execution successful.")

        return True

    except (IOError, OSError) as e:
        print(f"Error: Failed to read the file. {e}", file=sys.stderr)
        return False
    except MemoryError:
        print("Error: Out of memory. The file might be too large to process.", file=sys.stderr)
        return False
    finally:
        print(f"--- Finished processing: {file_path} ---\n")


if __name__ == "__main__":
    # --- Test Case Setup ---
    valid_file = "test_image.jpg"
    large_file = "large_image.png"
    bad_name_file = "bad'name;--.txt"
    try:
        with open(valid_file, "w") as f:
            f.write("This is a dummy image file.")
        with open(large_file, "w") as f:
            f.write("This file is to test the size check logic.")
        with open(bad_name_file, "w") as f:
            f.write("bad content")
    except IOError as e:
        print(f"Failed to set up test files: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Running 5 Test Cases ---
    print("====== Running Python Test Cases ======")
    
    # 1. Valid upload
    upload_image(valid_file)

    # 2. File does not exist
    upload_image("non_existent_file.gif")

    # 3. File path with traversal attempt (should be sanitized by os.path.basename)
    upload_image(f"../../dummy_dir/{valid_file}")

    # 4. Filename with invalid characters
    upload_image(bad_name_file)
    
    # 5. File is too large (conceptual test)
    # This test will pass since the file is small, but it demonstrates the check exists in the code.
    # To fail, the file would need to be > MAX_FILE_SIZE.
    print("Testing large file (will pass if its actual size is small, but demonstrates the check is in place)...")
    upload_image(large_file)

    # --- Test Case Cleanup ---
    if os.path.exists(valid_file):
        os.remove(valid_file)
    if os.path.exists(large_file):
        os.remove(large_file)
    if os.path.exists(bad_name_file):
        os.remove(bad_name_file)