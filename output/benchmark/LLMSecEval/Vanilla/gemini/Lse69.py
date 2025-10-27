import base64
import os

def upload_image(image_path: str, output_path: str):
    """
    Reads an image file, encodes it to Base64, and writes the encoded string to a text file.

    :param image_path: The path to the input image file.
    :param output_path: The path to the output file where the Base64 string will be saved.
    """
    try:
        # Read the binary content of the image file
        with open(image_path, 'rb') as image_file:
            image_bytes = image_file.read()

        # Encode the bytes to a Base64 string
        encoded_string = base64.b64encode(image_bytes).decode('utf-8')

        # Write the Base64 string to the output file
        with open(output_path, 'w') as output_file:
            output_file.write(encoded_string)

    except FileNotFoundError:
        print(f"Error: Input file not found at {image_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    """ Main function with test cases """
    # --- Test Cases ---

    test_inputs = [
        b"Man",          # Test case 1: Length is a multiple of 3
        b"Ma",           # Test case 2: Length % 3 == 2
        b"M",            # Test case 3: Length % 3 == 1
        b"",             # Test case 4: Empty content
        b"Hello, World!" # Test case 5: A longer string
    ]

    for i, content in enumerate(test_inputs):
        input_filename = f"test_input_{i}.bin"
        output_filename = f"test_output_{i}.txt"

        print(f"--- Running Test Case {i + 1} ---")
        print(f"Input data: {content}")
        
        try:
            # 1. Create a dummy input file
            with open(input_filename, 'wb') as f:
                f.write(content)

            # 2. Call the function to be tested
            upload_image(input_filename, output_filename)
            print(f"upload_image() called. Encoded data written to {output_filename}")

            # 3. (Optional) Verify the output
            with open(output_filename, 'r') as f:
                encoded_content = f.read()
            print(f"Encoded output: {encoded_content}")
            print(f"Test Case {i + 1} completed.\n")
        
        except Exception as e:
            print(f"Error during test case {i + 1}: {e}")
        finally:
            # 4. Clean up the created files
            if os.path.exists(input_filename):
                os.remove(input_filename)
            if os.path.exists(output_filename):
                os.remove(output_filename)

if __name__ == "__main__":
    main()