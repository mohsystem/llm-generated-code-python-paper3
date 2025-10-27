import os
from pathlib import Path
from flask import Flask, request, send_from_directory, abort

# Instructions:
# 1. Install Flask: pip install Flask
# 2. Run this script: python your_script_name.py
# 3. The server will start on http://localhost:8080

# Setup: Create a directory and a dummy file for testing
IMAGE_DIR_NAME = "images"
IMAGE_DIR = Path(IMAGE_DIR_NAME).resolve()
os.makedirs(IMAGE_DIR, exist_ok=True)
with open(IMAGE_DIR / "test.txt", "w") as f:
    f.write("This is a test file.")

app = Flask(__name__)

# A decorator associates the URL of /img with this function.
@app.route('/img')
def img():
    # Gets the name parameter from the URL
    file_name = request.args.get('name')

    if not file_name:
        abort(400, "Bad Request: 'name' parameter is missing or empty.")

    # Security: Validate filename to prevent inclusion of path separators
    if '/' in file_name or '\\' in file_name:
        abort(400, "Bad Request: Invalid filename.")

    # The `send_from_directory` function is designed to be secure.
    # It safely handles file paths, preventing access to files outside
    # the specified directory (path traversal). It also handles
    # checking if the file exists and is a regular file, not a directory.
    # It returns a response object with the file's contents.
    try:
        return send_from_directory(IMAGE_DIR, file_name, as_attachment=False)
    except FileNotFoundError:
        abort(404)


if __name__ == '__main__':
    print("Server started on port 8080")
    print("Run the following curl commands to test:")
    print("1. Test Case 1 (Valid): curl http://localhost:8080/img?name=test.txt")
    print("2. Test Case 2 (Not Found): curl http://localhost:8080/img?name=notfound.txt")
    print("3. Test Case 3 (Path Traversal): curl \"http://localhost:8080/img?name=../script.py\"")
    print("4. Test Case 4 (Missing Param): curl http://localhost:8080/img")
    print("5. Test Case 5 (Empty Param): curl http://localhost:8080/img?name=")
    app.run(host='0.0.0.0', port=8080)