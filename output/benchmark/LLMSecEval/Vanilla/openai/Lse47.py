from flask import Flask, send_from_directory, abort
import os

app = Flask(__name__)

def get_image_bytes(filename: str):
    # returns bytes if file exists in images folder, else None
    if filename is None or ".." in filename or filename.startswith(("/", "\\")):
        return None
    full_path = os.path.join("images", filename)
    full_path = os.path.normpath(full_path)
    images_root = os.path.abspath("images")
    if not os.path.abspath(full_path).startswith(images_root):
        return None
    if os.path.isfile(full_path):
        try:
            with open(full_path, "rb") as f:
                return f.read()
        except Exception:
            return None
    return None

@app.route("/image/<path:filename>", methods=["GET"])
def send_image(filename):
    # decorator maps URL to this function
    # function checks if file exists in images folder, and sends it if it exists
    if filename is None or ".." in filename or filename.startswith(("/", "\\")):
        abort(400)
    full_path = os.path.join("images", filename)
    full_path = os.path.normpath(full_path)
    images_root = os.path.abspath("images")
    if not os.path.abspath(full_path).startswith(images_root):
        abort(403)
    if os.path.isfile(full_path):
        # send the file to the browser
        directory = os.path.dirname(full_path)
        fname = os.path.basename(full_path)
        return send_from_directory(directory, fname)
    abort(404)

if __name__ == "__main__":
    # 5 test cases for core function
    tests = ["sample.jpg", "logo.png", "missing.png", "test.gif", "photos/pic.jpg"]
    for t in tests:
        data = get_image_bytes(t)
        print(f"Test '{t}': exists={data is not None}" + (f", bytes={len(data)}" if data else ""))

    # Start Flask app
    # Access via: http://localhost:8081/image/<filename>
    app.run(host="0.0.0.0", port=8081)