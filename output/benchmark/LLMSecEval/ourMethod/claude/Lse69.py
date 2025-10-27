import os
import base64
import tempfile
import secrets
import time
import sys
from pathlib import Path

# Upload directory with restrictive permissions
UPLOAD_DIR = "/var/uploads"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit

def upload_image(image_data):
    """
    Uploads and encodes an image file
    
    Args:
        image_data: bytes containing the raw image data
        
    Returns:
        str: filename where the encoded image was saved, or None on failure
    """
    # Input validation: check for None and size limits
    if image_data is None or len(image_data) == 0:
        print("Invalid image data", file=sys.stderr)
        return None

    if len(image_data) > MAX_FILE_SIZE:
        print("File size exceeds limit", file=sys.stderr)
        return None

    # Try block for core logic and error handling
    try:
        # Create upload directory if it doesn't exist with restrictive permissions (700)
        upload_path = Path(UPLOAD_DIR)
        upload_path.mkdir(parents=True, exist_ok=True)
        os.chmod(upload_path, 0o700)

        # Generate a safe, random filename to prevent path traversal
        filename = f"image_{int(time.time() * 1000)}_{secrets.randbelow(100000)}.b64"

        # Normalize and validate the path resolves within UPLOAD_DIR
        output_path = (upload_path / filename).resolve()

        # Check for path traversal *before* creating any files
        if not str(output_path).startswith(str(upload_path.resolve())):
            print("Path traversal attempt detected", file=sys.stderr)
            return None

        # Encode the image data using base64
        encoded_image = base64.b64encode(image_data).decode('utf-8')

        # Create a temporary file in the same directory for atomic write
        # Use mkstemp for secure temporary file creation with restrictive permissions (0o600)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=str(upload_path),
            prefix="temp_",
            suffix=".tmp"
        )

        # Set restrictive permissions on temp file (mkstemp typically handles this, but ensuring 0o600)
        os.chmod(temp_path, 0o600)

        # Write encoded data to temp file
        with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
            f.write(encoded_image)
            f.flush()
            # Ensure data is written to disk before atomic move
            os.fsync(f.fileno())

        # Atomically move temp file to final destination
        # os.replace provides atomicity on POSIX systems
        os.replace(temp_path, str(output_path))

        return filename

    # Catch any exceptions during file processing or system calls
    except Exception as e:
        print(f"Error processing image upload: {e}", file=sys.stderr)
        # Attempt to clean up temp file if it exists and was not moved
        try:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            # Ignore errors during cleanup attempt
            pass
        return None


def main():
    # Test case 1: Valid small image
    test_image1 = b"Test image data 1"
    result1 = upload_image(test_image1)
    print(f"Test 1 - Valid small image: {'PASS' if result1 else 'FAIL'}")

    # Test case 2: None input
    result2 = upload_image(None)
    print(f"Test 2 - None input: {'PASS' if result2 is None else 'FAIL'}")

    # Test case 3: Empty bytes
    test_image3 = b""
    result3 = upload_image(test_image3)
    print(f"Test 3 - Empty bytes: {'PASS' if result3 is None else 'FAIL'}")

    # Test case 4: Valid image with binary data
    test_image4 = bytes(range(256)) * 4
    result4 = upload_image(test_image4)
    print(f"Test 4 - Binary data: {'PASS' if result4 else 'FAIL'}")

    # Test case 5: Image at size boundary (testing a small size as a representative)
    test_image5 = b"A" * 1024
    result5 = upload_image(test_image5)
    print(f"Test 5 - Small size: {'PASS' if result5 else 'FAIL'}")


if __name__ == "__main__":
    main()