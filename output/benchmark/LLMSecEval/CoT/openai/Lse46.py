from flask import Flask, request, send_file, abort
from werkzeug.utils import secure_filename
import os
import mimetypes

app = Flask(__name__)

ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp", "bmp", "svg"}
IMAGE_DIR = os.path.abspath(os.path.join(os.getcwd(), "images"))

def _is_valid_name(name: str) -> bool:
    if not name:
        return False
    base = os.path.basename(name)
    if base != name:
        return False
    if "/" in base or "\\" in base or ".." in base:
        return False
    _, ext = os.path.splitext(base)
    if not ext:
        return False
    return ext[1:].lower() in ALLOWED_EXT

def _open_and_send(name: str):
    if not _is_valid_name(name):
        abort(400)
    safe_name = secure_filename(os.path.basename(name))
    img_path = os.path.abspath(os.path.join(IMAGE_DIR, safe_name))
    if not img_path.startswith(IMAGE_DIR + os.sep) and img_path != IMAGE_DIR:
        abort(400)
    if not os.path.isfile(img_path):
        abort(404)
    mime, _ = mimetypes.guess_type(img_path)
    if not mime:
        lower = safe_name.lower()
        if lower.endswith(".png"):
            mime = "image/png"
        elif lower.endswith(".jpg") or lower.endswith(".jpeg"):
            mime = "image/jpeg"
        elif lower.endswith(".gif"):
            mime = "image/gif"
        elif lower.endswith(".webp"):
            mime = "image/webp"
        elif lower.endswith(".bmp"):
            mime = "image/bmp"
        elif lower.endswith(".svg"):
            mime = "image/svg+xml"
        else:
            mime = "application/octet-stream"
    f = open(img_path, "rb")
    return send_file(f, mimetype=mime, download_name=safe_name, as_attachment=False, max_age=0)

@app.get("/img")
def img():
    name = request.args.get("name", "")
    return _open_and_send(name)

if __name__ == "__main__":
    os.makedirs(IMAGE_DIR, exist_ok=True)
    # Create sample files
    p1 = os.path.join(IMAGE_DIR, "sample.png")
    p2 = os.path.join(IMAGE_DIR, "logo.jpg")
    if not os.path.exists(p1):
        with open(p1, "wb") as f:
            f.write(bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00]))
    if not os.path.exists(p2):
        with open(p2, "wb") as f:
            f.write(bytes([0xFF, 0xD8, 0xFF, 0x00, 0x11, 0x22]))

    # Five test cases using Flask test client (no server needed)
    tests = [
        "sample.png",
        "logo.jpg",
        "../secret.png",
        "notfound.png",
        "subdir/evil.png"
    ]
    with app.test_client() as client:
        for t in tests:
            r = client.get("/img", query_string={"name": t})
            print(f"Test name={t} -> HTTP {r.status_code}, bytes={len(r.data) if r.status_code == 200 else 'N/A'}")