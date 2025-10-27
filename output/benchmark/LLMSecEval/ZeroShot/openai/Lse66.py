import os
import threading
import time
import urllib.request
import urllib.error
import secrets
from flask import Flask, request, Response

MAX_SIZE = 1 * 1024 * 1024  # 1 MB
UPLOADS_DIR = "uploads"

app = Flask(__name__)

def sanitize_filename(name: str) -> str:
    if not name:
        name = "file.pdf"
    # keep base name only
    name = name.replace("\\", "/").split("/")[-1]
    # remove trailing dots
    name = name.rstrip(".")
    # allow only safe chars
    cleaned = []
    for ch in name:
        if ch.isalnum() or ch in ("-", "_", "."):
            cleaned.append(ch)
        else:
            cleaned.append("_")
    name = "".join(cleaned)
    lower = name.lower()
    if lower.endswith(".pdf"):
        name = name[:-4]
    if not name:
        name = "file"
    if len(name) > 100:
        name = name[:100]
    return name

def ensure_uploads_dir():
    os.makedirs(UPLOADS_DIR, mode=0o700, exist_ok=True)

def is_pdf_header(data: bytes) -> bool:
    return len(data) >= 5 and data[:5] == b"%PDF-"

def generate_safe_filename(original_filename: str) -> str:
    base = sanitize_filename(original_filename)
    suffix = secrets.token_hex(8)
    fname = f"{base}_{int(time.time()*1000)}_{suffix}.pdf"
    return fname[:255]

def save_pdf(data: bytes, original_filename: str) -> str:
    if not data:
        raise ValueError("Empty file")
    if len(data) > MAX_SIZE:
        raise ValueError("File too large")
    if not is_pdf_header(data):
        raise ValueError("Invalid PDF header")
    ensure_uploads_dir()
    tmp_name = f"upload_{secrets.token_hex(6)}.tmp"
    tmp_path = os.path.join(UPLOADS_DIR, tmp_name)
    final_name = generate_safe_filename(original_filename)
    final_path = os.path.join(UPLOADS_DIR, final_name)
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, final_path)
    os.chmod(final_path, 0o600)
    return os.path.abspath(final_path)

@app.route("/upload", methods=["POST"])
def upload():
    try:
        ct = request.headers.get("Content-Type", "").lower()
        if request.files:
            f = request.files.get("file")
            if not f:
                return Response("No file part", status=400)
            data = f.read()
            orig = f.filename or request.headers.get("X-Filename", "upload.pdf")
        elif ct.startswith("application/pdf"):
            data = request.get_data(cache=False, as_text=False)
            orig = request.headers.get("X-Filename", "upload.pdf")
        else:
            return Response("Unsupported Media Type - must be application/pdf", status=415)
        if data is None:
            return Response("No data", status=400)
        path = save_pdf(data, orig)
        return Response(f"Saved: {path}", status=201, mimetype="text/plain")
    except ValueError as ve:
        return Response(str(ve), status=400, mimetype="text/plain")
    except Exception:
        return Response("Internal Server Error", status=500, mimetype="text/plain")

def run_server():
    app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False, threaded=True)

def http_post(data: bytes, content_type: str, filename: str):
    req = urllib.request.Request("http://127.0.0.1:5001/upload", method="POST", data=data)
    req.add_header("Content-Type", content_type)
    if filename is not None:
        req.add_header("X-Filename", filename)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return f"{resp.status} {body}"
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return f"{e.code} {body}"
    except Exception as e:
        return f"ERR {str(e)}"

if __name__ == "__main__":
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(0.5)

    valid_pdf = b"%PDF-1.7\n%Test PDF\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    print("Test1:", http_post(valid_pdf, "application/pdf", "test.pdf"))
    print("Test2:", http_post(valid_pdf, "text/plain", "test.pdf"))
    print("Test3:", http_post(b"HELLO", "application/pdf", "doc.pdf"))
    print("Test4:", http_post(valid_pdf, "application/pdf", "../evil.pdf"))

    big = bytearray(MAX_SIZE + 10)
    big[:5] = b"%PDF-"
    print("Test5:", http_post(bytes(big), "application/pdf", "big.pdf"))