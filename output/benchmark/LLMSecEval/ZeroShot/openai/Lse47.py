from flask import Flask, send_file, abort, Response
import os
import mimetypes

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
IMAGES_DIR = os.path.join(BASE_DIR, "images")
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

def ensure_test_images():
    os.makedirs(IMAGES_DIR, exist_ok=True)
    sample_png = os.path.join(IMAGES_DIR, "sample.png")
    photo_jpg = os.path.join(IMAGES_DIR, "photo.jpg")
    if not os.path.exists(sample_png):
        with open(sample_png, "wb") as f:
            f.write(b"\x89PNG\x00\x00\x00\x00")
    if not os.path.exists(photo_jpg):
        with open(photo_jpg, "wb") as f:
            f.write(b"JPEGDATA")

def is_allowed(filename: str) -> bool:
    lower = filename.lower()
    _, ext = os.path.splitext(lower)
    return ext in ALLOWED_EXT

# Decorator indicates which URL triggers the function
@app.route("/images/<path:filename>", methods=["GET"])
def serve_image(filename: str):
    if not is_allowed(filename):
        abort(403)
    # Normalize and ensure path is inside IMAGES_DIR
    full_path = os.path.normpath(os.path.join(IMAGES_DIR, filename))
    if not full_path.startswith(IMAGES_DIR):
        abort(400)
    if not os.path.isfile(full_path):
        abort(404)
    ctype, _ = mimetypes.guess_type(full_path)
    if ctype is None:
        # conservative default
        ctype = "application/octet-stream"
    resp = send_file(full_path, mimetype=ctype, conditional=True)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp

if __name__ == "__main__":
    ensure_test_images()
    # 5 test cases using Flask's test client
    with app.test_client() as client:
        print(client.get("/images/sample.png").status_code)     # 200
        print(client.get("/images/none.png").status_code)       # 404
        print(client.get("/images/../secret.txt").status_code)  # 400
        print(client.get("/images/bad.txt").status_code)        # 403
        print(client.get("/images/photo.jpg").status_code)      # 200