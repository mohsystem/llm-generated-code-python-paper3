import os
from pathlib import Path
# To run the web server part, you need to install Flask:
# pip install Flask
from flask import Flask, send_from_directory, abort

# --- Web Server Implementation (using Flask) ---

# The code for the server is defined here. The @app.route decorator tells 
# Flask what URL should trigger our function. This server is not started 
# in the main execution block below to allow for console-based testing.
app = Flask(__name__)
IMAGE_DIR = "images"

@app.route('/images/<path:filename>')
def serve_image(filename):
    """
    This function is triggered by requests to /images/<filename>.
    It checks if the file exists and serves it securely.
    """
    image_dir_path = Path(IMAGE_DIR).resolve()
    try:
        # send_from_directory securely handles pathing and prevents directory traversal.
        return send_from_directory(image_dir_path, filename)
    except FileNotFoundError:
        abort(404, description=f"File '{filename}' not found.")


# --- Console-based Simulation and Testing ---

def handle_file_request_logic(filename):
    """
    Simulates the core logic for console-based testing without running a server.
    Checks if a file exists in the images folder.
    """
    # Basic security check to prevent directory traversal
    if not filename or '/' in filename or '\\' in filename:
        return f"HTTP 400 Bad Request: Invalid filename '{filename}'."

    file_path = Path(IMAGE_DIR) / filename
    
    if file_path.is_file():
        return f"HTTP 200 OK: Sending file '{file_path}' to the browser."
    else:
        return f"HTTP 404 Not Found: File '{file_path}' does not exist."

def setup_dummy_files():
    """Sets up a dummy 'images' directory with some files for testing."""
    image_dir_path = Path(IMAGE_DIR)
    try:
        image_dir_path.mkdir(exist_ok=True)
        (image_dir_path / "cat.jpg").touch()
        (image_dir_path / "dog.png").touch()
        (image_dir_path / "bird.gif").touch()
    except OSError as e:
        print(f"Error creating dummy files: {e}")

# Main execution block for testing the logic
if __name__ == "__main__":
    # 1. Setup the environment
    setup_dummy_files()

    # 2. Run test cases using the simulated logic function
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Requesting an existing file
    print("Test 1 (cat.jpg):")
    print(f"  {handle_file_request_logic('cat.jpg')}")

    # Test Case 2: Requesting another existing file
    print("Test 2 (dog.png):")
    print(f"  {handle_file_request_logic('dog.png')}")

    # Test Case 3: Requesting a non-existent file
    print("Test 3 (lion.jpg):")
    print(f"  {handle_file_request_logic('lion.jpg')}")

    # Test Case 4: Attempting directory traversal (should be blocked)
    print("Test 4 (../somefile.txt):")
    print(f"  {handle_file_request_logic('../somefile.txt')}")

    # Test Case 5: Requesting an empty/invalid filename
    print("Test 5 (empty string):")
    print(f"  {handle_file_request_logic('')}")

    print("\n--- Test Cases Finished ---")
    print("\nTo run the actual web server, uncomment the line 'app.run(debug=True)' at the end of this file.")
    # To start the server, you would uncomment the following line:
    # app.run(debug=True, port=5000)