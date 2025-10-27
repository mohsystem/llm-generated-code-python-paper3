# To run this code, you need to install Flask:
# pip install Flask

import os
from flask import Flask, send_from_directory, abort

# The app object is a global instance of Flask.
app = Flask(__name__)
IMAGE_DIR = os.path.abspath("images")

# This decorator tells Flask that the URL "/images/<filename>" should trigger our function.
# Using <path:filename> is safer as it allows Flask to handle path-like structures
# while send_from_directory provides the primary security against traversal.
@app.route('/images/<path:filename>')
def serve_image(filename):
    """
    Checks if the file exists in the images folder.
    If the file exists it sends the file to the browser.
    """
    # --- Security ---
    # `send_from_directory` is the recommended secure way to send static files in Flask.
    # It automatically handles security checks to prevent path traversal attacks
    # by ensuring the resolved path is within the specified directory.
    # It also handles 404 Not Found errors if the file doesn't exist.
    try:
        return send_from_directory(IMAGE_DIR, filename, as_attachment=False)
    except Exception as e:
        # Abort with a 404 if send_from_directory raises an exception (e.g., NotFound)
        # This also catches other potential errors.
        print(f"Error serving {filename}: {e}")
        abort(404)

def main():
    """ Main function to set up test files and run the Flask server. """
    # Setup test environment
    if not os.path.exists(IMAGE_DIR):
        os.makedirs(IMAGE_DIR)

    # Create dummy files for testing
    with open(os.path.join(IMAGE_DIR, "test1.png"), "wb") as f:
        f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89')
    with open(os.path.join(IMAGE_DIR, "safe.txt"), "w") as f:
        f.write("This is a safe file.")

    port = 5000
    print(f"Server started on port {port}")
    print("--- Test Cases (run in another terminal) ---")
    print(f"1) Access a valid file: curl http://localhost:{port}/images/test1.png --output test1_out.png")
    print(f"2) Access another valid file: curl http://localhost:{port}/images/safe.txt")
    print(f"3) Access a non-existent file: curl -i http://localhost:{port}/images/nonexistent.jpg")
    print(f"4) Attempt path traversal (should fail with 404): curl -i http://localhost:{port}/images/../app.py")
    print(f"5) Attempt another path traversal: curl -i http://localhost:{port}/images/..%2fapp.py")
    
    # Run the Flask web server
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    main()