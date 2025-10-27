# 1) Problem understanding:
# - Provide a simple web application to upload files to server.
# - GET / -> HTML form; POST /upload -> process multipart/form-data.
# 2) Security requirements:
# - Size limit, sanitize filename, whitelist extensions, basic content sniffing, randomize storage.
# 3) Secure coding generation: implement helpers and WSGI app accordingly.

import os
import sys
import io
import json
import secrets
from wsgiref.simple_server import make_server
from cgi import FieldStorage
from html import escape

MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXT = {"txt", "png", "jpg", "jpeg", "pdf"}
UPLOAD_DIR = "uploads"

def sanitize_filename(filename: str) -> str:
    if not filename:
        return "file"
    base = filename.replace("\\", "/").split("/")[-1]
    clean = []
    for ch in base:
        if 32 <= ord(ch) <= 126 and (ch.isalnum() or ch in "._-"):
            clean.append(ch)
    name = "".join(clean) or "file"
    if name.startswith("."):
        name = "file" + name
    return name

def get_extension_lower(filename: str) -> str:
    if not filename:
        return ""
    parts = filename.rsplit(".", 1)
    return parts[1].lower() if len(parts) == 2 else ""

def is_allowed_extension(filename: str) -> bool:
    return get_extension_lower(filename) in ALLOWED_EXT

def is_safe_content(filename: str, data: bytes) -> bool:
    ext = get_extension_lower(filename)
    if data is None:
        return False
    if ext == "png":
        sig = b"\x89PNG\r\n\x1a\n"
        return data.startswith(sig)
    if ext in ("jpg", "jpeg"):
        return len(data) >= 2 and data[0] == 0xFF and data[1] == 0xD8
    if ext == "pdf":
        return data.startswith(b"%PDF-")
    if ext == "txt":
        sample = data[:4096]
        for b in sample:
            if b == 0 or b < 9 or (b > 126 and b < 160):
                return False
        return True
    return False

def random_stored_name(filename: str) -> str:
    ext = get_extension_lower(filename)
    token = secrets.token_hex(16)
    return f"{token}.{ext}" if ext else token

def form_page() -> bytes:
    html = """<!doctype html><html><head><meta charset="utf-8"><title>Secure Upload</title></head>
<body><h1>Upload a file</h1>
<form method="POST" action="/upload" enctype="multipart/form-data">
<input type="file" name="file" required>
<button type="submit">Upload</button>
</form></body></html>"""
    return html.encode("utf-8")

def ensure_upload_dir():
    if not os.path.isdir(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR, exist_ok=True)

def handle_upload(environ, start_response):
    # Enforce size via CONTENT_LENGTH if present
    try:
        length = int(environ.get("CONTENT_LENGTH", "0"))
    except ValueError:
        length = 0
    if length > MAX_UPLOAD_SIZE:
        start_response("413 Payload Too Large", [("Content-Type", "application/json; charset=utf-8")])
        return [json.dumps({"status": "error", "message": "Payload too large"}).encode("utf-8")]
    # Parse multipart using cgi.FieldStorage
    # Wrap wsgi.input with a limiting stream
    wsgi_input = environ["wsgi.input"]
    data = wsgi_input.read(length) if length > 0 else wsgi_input.read(MAX_UPLOAD_SIZE + 1)
    if len(data) > MAX_UPLOAD_SIZE:
        start_response("413 Payload Too Large", [("Content-Type", "application/json; charset=utf-8")])
        return [json.dumps({"status": "error", "message": "Payload too large"}).encode("utf-8")]
    fp = io.BytesIO(data)
    env = environ.copy()
    env["wsgi.input"] = fp
    fs = FieldStorage(fp=fp, environ=env, keep_blank_values=False)
    if "file" not in fs or not getattr(fs["file"], "filename", ""):
        start_response("200 OK", [("Content-Type", "application/json; charset=utf-8")])
        return [json.dumps({"status": "error", "message": "No file uploaded"}).encode("utf-8")]
    file_item = fs["file"]
    client_name = sanitize_filename(file_item.filename)
    if not is_allowed_extension(client_name):
        start_response("200 OK", [("Content-Type", "application/json; charset=utf-8")])
        return [json.dumps({"status": "error", "message": "Disallowed file type"}).encode("utf-8")]
    # Read content safely
    file_data = file_item.file.read(MAX_UPLOAD_SIZE + 1)
    if len(file_data) == 0:
        start_response("200 OK", [("Content-Type", "application/json; charset=utf-8")])
        return [json.dumps({"status": "error", "message": "Empty file"}).encode("utf-8")]
    if len(file_data) > MAX_UPLOAD_SIZE:
        start_response("413 Payload Too Large", [("Content-Type", "application/json; charset=utf-8")])
        return [json.dumps({"status": "error", "message": "Payload too large"}).encode("utf-8")]
    if not is_safe_content(client_name, file_data):
        start_response("200 OK", [("Content-Type", "application/json; charset=utf-8")])
        return [json.dumps({"status": "error", "message": "File content not allowed"}).encode("utf-8")]
    ensure_upload_dir()
    stored = random_stored_name(client_name)
    dest = os.path.abspath(os.path.join(UPLOAD_DIR, stored))
    if not dest.startswith(os.path.abspath(UPLOAD_DIR) + os.sep):
        start_response("200 OK", [("Content-Type", "application/json; charset=utf-8")])
        return [json.dumps({"status": "error", "message": "Path traversal detected"}).encode("utf-8")]
    tmp_path = os.path.join(UPLOAD_DIR, f"up_{secrets.token_hex(6)}.part")
    with open(tmp_path, "wb") as f:
        f.write(file_data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, dest)
    start_response("200 OK", [("Content-Type", "application/json; charset=utf-8")])
    return [json.dumps({"status": "ok", "original": client_name, "stored": stored, "size": len(file_data)}).encode("utf-8")]

def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO", "/")
    if method == "GET" and path == "/":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [form_page()]
    if method == "POST" and path == "/upload":
        return handle_upload(environ, start_response)
    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return [b"Not Found"]

def run_server():
    ensure_upload_dir()
    httpd = make_server("127.0.0.1", 8081, app)
    print("Python server running at http://127.0.0.1:8081/")
    httpd.serve_forever()

if __name__ == "__main__":
    # 4) Code review: tests for helpers (5 test cases)
    assert sanitize_filename("../../evil.txt") == "evil.txt"
    assert is_allowed_extension("a.PNG") is True
    assert is_allowed_extension("a.exe") is False
    assert is_safe_content("x.png", b"\x89PNG\r\n\x1a\nrest")
    rn = random_stored_name("doc.pdf"); assert rn.endswith(".pdf")
    # 5) Secure code output: run server
    run_server()