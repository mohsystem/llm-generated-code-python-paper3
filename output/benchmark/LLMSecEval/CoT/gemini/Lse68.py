import base64
import os

# Simulates a database using a dictionary.
image_database = {}

def upload_image(file_path: str):
    """
    Reads an image from a file path, converts it to Base64,
    and inserts it into a simulated database.
    
    Args:
        file_path (str): The path to the image file.
    """
    try:
        # Security: Prevent path traversal by extracting only the filename.
        file_name = os.path.basename(file_path)

        # Use 'with' statement to ensure the file is closed automatically.
        # 'rb' mode is crucial for reading non-text files like images.
        with open(file_path, 'rb') as image_file:
            image_data = image_file.read()

        # Encode the binary data to a Base64 string.
        # .decode('utf-8') converts the result from bytes to a string.
        base64_string = base64.b64encode(image_data).decode('utf-8')

        # Insert into the simulated database.
        image_database[file_name] = base64_string
        print(f"Successfully uploaded and encoded '{file_name}'.")

    except FileNotFoundError:
        print(f"Error: File not found at path: {file_path}")
    except IOError as e:
        print(f"Error processing file '{file_path}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred with '{file_path}': {e}")

def main():
    """ Main function to run test cases. """
    # --- Test Case Setup ---
    # Create dummy files for testing.
    try:
        with open("test1.txt", "w") as f:
            f.write("Hello World")
        with open("test2.jpg", "wb") as f:
            f.write(b'\xff\xd8\xff\xe0')
        with open("test3.txt", "w") as f:
            pass # Create an empty file
    except IOError as e:
        print(f"Failed to create test files: {e}")
        return

    print("--- Running Test Cases ---")
    # Test Case 1: A valid text file.
    upload_image("test1.txt")

    # Test Case 2: A valid (simulated) image file.
    upload_image("test2.jpg")

    # Test Case 3: An empty file.
    upload_image("test3.txt")

    # Test Case 4: A non-existent file.
    upload_image("nonexistent.png")

    # Test Case 5: A path traversal attempt.
    # os.path.basename will correctly extract 'test1.txt'.
    upload_image(os.path.join("..", "test1.txt"))
    
    print("\n--- Simulated Database Content ---")
    for name, data in image_database.items():
        # Limiting data length for clean printing.
        data_preview = data[:30] + '...' if len(data) > 30 else data
        print(f"FileName: {name}, Base64: {data_preview}")
    print("--------------------------------\n")

    # --- Test Case Cleanup ---
    try:
        if os.path.exists("test1.txt"):
            os.remove("test1.txt")
        if os.path.exists("test2.jpg"):
            os.remove("test2.jpg")
        if os.path.exists("test3.txt"):
            os.remove("test3.txt")
    except OSError as e:
        print(f"Failed to clean up test files: {e}")


if __name__ == "__main__":
    main()