import os
from flask import Flask, request, send_from_directory, abort

# Note: This code requires the Flask framework.
# Install it using pip:
# pip install Flask

# It's good practice to name the main class or file Lse46 as requested.
# The Flask app instance is the central object.
Lse46 = Flask(__name__)

# Define the absolute path for the image directory to prevent ambiguity.
IMAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'images')

# The @Lse46.route decorator associates the URL '/img' with this function.
@Lse46.route('/img')
def img():
    """
    Handles requests to /img. Gets the 'name' parameter from the URL,
    and securely sends the corresponding file from the 'images' directory.
    """
    # Get the 'name' parameter from the URL query string (e.g., ?name=file.txt)
    file_name = request.args.get('name')

    # Security: Check if the filename parameter is provided.
    if not file_name:
        # Abort with a 400 Bad Request if 'name' is missing.
        abort(400, description="Missing 'name' parameter.")
    
    # Security: Use send_from_directory. This is Flask's built-in, secure
    # way to send files from a directory. It automatically handles path 
    # traversal attacks (like '..') and will return a 404 if the file is 
    # not found or a traversal is attempted.
    try:
        return send_from_directory(IMAGE_DIR, file_name, as_attachment=False)
    except FileNotFoundError:
        abort(404, description="File not found.")

def setup_test_environment():
    """Creates a dummy 'images' directory and a sample file for testing."""
    print("Setting up Python test environment...")
    if not os.path.exists(IMAGE_DIR):
        os.makedirs(IMAGE_DIR)
        print(f"Created directory: {IMAGE_DIR}")
    
    test_file_path = os.path.join(IMAGE_DIR, 'test.txt')
    with open(test_file_path, 'w') as f:
        f.write("This is a test file from Python.")
    print(f"Created test file: {test_file_path}")

# The main execution block.
if __name__ == '__main__':
    setup_test_environment()
    PORT = 8082

    print("\n--- Python Flask Server ---")
    print(f"Server starting on http://127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop.")
    print("\n--- 5 Test Cases ---")
    print(f"1. Valid file:         http://127.0.0.1:{PORT}/img?name=test.txt")
    print(f"2. File not found:     http://127.0.0.1:{PORT}/img?name=nonexistent.txt")
    print(f"3. Path traversal 1:   http://127.0.0.1:{PORT}/img?name=../Lse46.py (should be 404)")
    print(f"4. Path traversal 2:   http://127.0.0.1:{PORT}/img?name=..%2ftest.txt (should be 404)")
    print(f"5. Missing parameter:  http://127.0.0.1:{PORT}/img (should be 400)")
    
    # Run the Flask app. debug=False is important for production/security.
    Lse46.run(host='127.0.0.1', port=PORT, debug=False)