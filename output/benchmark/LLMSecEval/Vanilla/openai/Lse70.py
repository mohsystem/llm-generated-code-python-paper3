import os
from flask import Flask, request, jsonify

app = Flask(__name__)

def ensure_uploads_dir():
    os.makedirs("uploads", exist_ok=True)

def sanitize_filename(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/"))
    base = base.replace("..", "")
    return base or "upload.bin"

# The upload_file function: saves data under uploads directory. Returns absolute path string.
def upload_file(filename: str, data: bytes) -> str:
    ensure_uploads_dir()
    safe = sanitize_filename(filename)
    path = os.path.abspath(os.path.join("uploads", safe))
    with open(path, "wb") as f:
        f.write(data)
    return path

@app.route("/upload", methods=["POST"])
def http_upload():
    if 'file' in request.files:
        f = request.files['file']
        filename = sanitize_filename(f.filename or "upload.bin")
        data = f.read()
        saved = upload_file(filename, data)
        return jsonify({"saved": saved})
    else:
        filename = request.args.get("filename", "")
        if not filename:
            return jsonify({"error": "Missing filename query parameter"}), 400
        data = request.get_data() or b""
        saved = upload_file(filename, data)
        return jsonify({"saved": saved})

if __name__ == "__main__":
    # 5 test cases calling upload_file directly
    print(upload_file("hello.txt", b"Hello, World!"))
    print(upload_file("data.bin", bytes([0,1,2,3,4,5])))
    print(upload_file("image.jpg", bytes([0xFF, 0xD8, 0x00, 0x01])))
    print(upload_file("../evil/../../should_not_escape.txt", b"safe"))
    print(upload_file("unicode_файл.txt", "Привет".encode("utf-8")))
    # Start server on port 8081
    app.run(host="0.0.0.0", port=8081)