import base64
import os
import sys
import shutil

def upload_image(image_path: str, output_path: str):
    """
    Reads an image file, encodes it to Base64, and writes the result to an output file.
    
    :param image_path: The path to the input image file.
    :param output_path: The path to the output file for the Base64 string.
    :return: The path to the output file on success, None on failure.
    """
    # Security: Basic path validation. A robust solution would use os.path.realpath
    # and check if the path is within a whitelisted base directory.
    if ".." in os.path.normpath(image_path).split(os.sep) or \
       ".." in os.path.normpath(output_path).split(os.sep):
        print("Error: Path traversal attempt detected.", file=sys.stderr)
        return None
    
    try:
        # Security: Ensure the output directory exists before writing.
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True) # exist_ok=True prevents race conditions

        # Read the image file in binary mode. `with` ensures the file is closed.
        # This approach loads the whole file into memory, which is not ideal for very large files.
        # A streaming approach would be more secure against resource exhaustion.
        with open(image_path, 'rb') as image_file:
            image_data = image_file.read()

        # Encode the binary data using Base64.
        encoded_data = base64.b64encode(image_data)

        # Write the encoded data to the output file.
        with open(output_path, 'wb') as output_file:
            output_file.write(encoded_data)
            
        return output_path

    except FileNotFoundError:
        print(f"Error: Input file not found at '{image_path}'.", file=sys.stderr)
        return None
    except IOError as e:
        print(f"Error during file operation: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None

# --- Main for Test Cases ---
if __name__ == "__main__":
    # Setup test environment
    temp_dir = "temp_test_python"
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir)

    dummy_image_path = os.path.join(temp_dir, "test_image.jpg")
    empty_image_path = os.path.join(temp_dir, "empty.jpg")

    # Create dummy image file
    with open(dummy_image_path, 'wb') as f:
        f.write(b'\xff\xd8\xff\xe0\x01\x02\x03\x04') # Fake JPEG data
    
    # Create empty file
    with open(empty_image_path, 'w') as f:
        pass

    print("--- Python Test Cases ---")
    
    # Test Case 1: Successful upload
    print("Test Case 1: Normal valid image path")
    output_path1 = os.path.join(temp_dir, "output1.txt")
    result1 = upload_image(dummy_image_path, output_path1)
    print(f"Success, output at: {result1}" if result1 else "Failed")
    if result1:
        with open(result1, 'r') as f:
            print(f"Content: {f.read()}")
    print()

    # Test Case 2: Non-existent image path
    print("Test Case 2: Non-existent image path")
    output_path2 = os.path.join(temp_dir, "output2.txt")
    result2 = upload_image("non_existent_image.jpg", output_path2)
    print(f"Success, output at: {result2}" if result2 else "Failed")
    print()

    # Test Case 3: Output to non-existent directory
    print("Test Case 3: Output to non-existent directory")
    output_path3 = os.path.join(temp_dir, "new_dir", "output3.txt")
    result3 = upload_image(dummy_image_path, output_path3)
    print(f"Success, output at: {result3}" if result3 else "Failed")
    print()

    # Test Case 4: Path traversal attempt
    print("Test Case 4: Path traversal attempt")
    output_path4 = os.path.join(temp_dir, "output4.txt")
    result4 = upload_image(dummy_image_path, "../output4.txt")
    print(f"Success, output at: {result4}" if result4 else "Failed")
    print()
    
    # Test Case 5: Empty input file
    print("Test Case 5: Empty input file")
    output_path5 = os.path.join(temp_dir, "output5.txt")
    result5 = upload_image(empty_image_path, output_path5)
    print(f"Success, output at: {result5}" if result5 else "Failed")
    if result5:
        with open(result5, 'r') as f:
            print(f"Content: {f.read()}")
    print()