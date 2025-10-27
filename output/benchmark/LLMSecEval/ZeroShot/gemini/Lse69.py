import os
import base64
from pathlib import Path

# Define a constant for the safe upload directory.
UPLOAD_DIR = Path("uploads").resolve()

def upload_image(image_path_str: str) -> bool:
    """
    Reads an image file from a path, encodes it to Base64, and saves the encoded
    string to a new file within the UPLOAD_DIR.
    This function is secured against path traversal attacks.

    :param image_path_str: The string path to the image file to upload.
    :return: True if the operation was successful, False otherwise.
    """
    if not image_path_str:
        print("Error: Image path cannot be empty.")
        return False
        
    try:
        # Create the upload directory if it doesn't exist.
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        
        # Resolve the user-provided path to its absolute, canonical path.
        # This resolves symlinks and '..' components.
        input_path = Path(image_path_str).resolve()
        
        # --- Security Check ---
        # Ensure the resolved path is inside our designated UPLOAD_DIR.
        # We check if UPLOAD_DIR is a parent of the resolved input path.
        if UPLOAD_DIR not in input_path.parents:
            print(f"Error: Path traversal attempt detected. Access denied for: {input_path}")
            return False

        # --- Sanity Checks ---
        if not input_path.exists():
            print(f"Error: File not found at {input_path}")
            return False
        if not input_path.is_file():
            print(f"Error: Path does not point to a file: {input_path}")
            return False

        # Read the image file in binary mode
        with open(input_path, "rb") as image_file:
            image_bytes = image_file.read()

        # Encode the binary data to Base64
        encoded_string = base64.b64encode(image_bytes).decode("utf-8")

        # Define the output file path safely inside the UPLOAD_DIR
        output_filename = f"{input_path.name}.b64"
        output_path = UPLOAD_DIR / output_filename

        # Write the Base64 string to the new file
        with open(output_path, "w") as output_file:
            output_file.write(encoded_string)

        print(f"Image successfully encoded and saved to: {output_path}")
        return True

    except (IOError, OSError, SecurityException) as e:
        print(f"An error occurred during file processing: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


def main():
    """Main function with test cases."""
    # Setup for test cases
    print("--- Setting up test environment ---")
    sensitive_file = Path("sensitive.txt")
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        (UPLOAD_DIR / "test_image.jpg").write_text("dummy image data")
        sensitive_file.write_text("secret data")
        print("Test environment created.")
        print("------------------------------------")
    except OSError as e:
        print(f"Failed to set up test environment: {e}")
        return

    print("\n--- Running Test Cases ---")

    # Test Case 1: Valid image file
    print("\n[Test 1] Processing a valid image file...")
    upload_image("uploads/test_image.jpg")

    # Test Case 2: File does not exist
    print("\n[Test 2] Processing a non-existent file...")
    upload_image("uploads/not_found.jpg")

    # Test Case 3: Path traversal attempt
    print("\n[Test 3] Processing with a path traversal attempt...")
    # Note: On some systems, `Path("uploads/../sensitive.txt").resolve()` will correctly
    # resolve to the path of `sensitive.txt` outside the upload dir, which our check will catch.
    upload_image("uploads/../sensitive.txt")

    # Test Case 4: Accessing a file outside the allowed directory
    print("\n[Test 4] Processing a file outside the upload directory...")
    upload_image("sensitive.txt")

    # Test Case 5: Path is a directory, not a file
    print("\n[Test 5] Processing a directory path...")
    upload_image("uploads")

    print("\n--- Test Cases Finished ---")


if __name__ == "__main__":
    main()