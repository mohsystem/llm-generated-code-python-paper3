import http.server
import socketserver
import os
import secrets
import string
import sys
from io import BytesIO

MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5MB
ALLOWED_EXT = {".txt", ".png", ".jpg", ".jpeg", ".pdf", ".gif"}

def sanitize_filename(name: str) -> str:
    base = os.path.basename(name or "")
    allowed = set(string.ascii_letters + string.digits + "._-")
    sanitized = "".join(c if c in allowed else "_" for c in base)
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    if "." not in sanitized:
        sanitized += ".bin"
    return sanitized

def get_extension(name: str) -> str:
    _, ext = os.path.splitext(name)
    return ext.lower()

def random_hex(n: int) -> str:
    return secrets.token_hex(n)

def save_uploaded_file(data: bytes, original_filename: str, content_type: str, max_size_bytes: int, upload_dir: str) -> str:
    if data is None:
        raise ValueError("No data")
    if not original_filename:
        raise ValueError("Missing filename")
    if len(data) == 0:
        raise ValueError("Empty upload")
    if len(data) > max_size_bytes:
        raise ValueError("File too large")
    os.makedirs(upload_dir, exist_ok=True)
    try:
        os.chmod(upload_dir, 0o700)
    except Exception:
        pass

    sanitized = sanitize_filename(original_filename)
    ext = get_extension(sanitized)
    if ext not in ALLOWED_EXT:
        raise ValueError("Disallowed file extension")

    unique = random_hex(12) + ext
    target = os.path.join(os.path.abspath(upload_dir), unique)

    # Ensure target is within upload_dir
    if not os.path.abspath(target).startswith(os.path.abspath(upload_dir) + os.sep):
        raise ValueError("Invalid upload path")

    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        try:
            os.remove(target)
        except Exception:
            pass
        raise
    return target

class UploadHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PyUpload/1.0"

    def do_GET(self):
        if self.path != "/":
            self.send_error(404, "Not Found")
            return
        html = """<!doctype html><html><head><meta charset='utf-8'><title>Python Upload</title></head>
<body>
<h1>Upload a file</h1>
<input type='file' id='f'><button id='u'>Upload</button>
<pre id='o'></pre>
<script>
document.getElementById('u').onclick=async ()=>{
  let f=document.getElementById('f').files[0];
  if(!f){alert('Choose a file');return;}
  let buf=await f.arrayBuffer();
  let r=await fetch('/upload',{method:'POST',headers:{'X-Filename':f.name,'Content-Type':'application/octet-stream','Content-Length':buf.byteLength},body:buf});
  document.getElementById('o').textContent=await r.text();
};
</script>
</body></html>"""
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/upload":
            self.send_error(404, "Not Found")
            return
        length = self.headers.get("Content-Length")
        filename = self.headers.get("X-Filename")
        if not length or not length.isdigit():
            self.send_error(411, "Length Required")
            return
        size = int(length)
        if size <= 0 or size > MAX_SIZE_BYTES:
            self.send_error(413, "Payload Too Large")
            return
        if not filename:
            self.send_error(400, "Missing X-Filename header")
            return
        content_type = self.headers.get("Content-Type") or "application/octet-stream"
        data = self.rfile.read(size)
        try:
            saved = save_uploaded_file(data, filename, content_type, MAX_SIZE_BYTES, "uploads_py")
            msg = f"Saved: {os.path.basename(saved)}"
            body = msg.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            msg = f"Upload failed: {str(e)}".encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

def run_tests():
    print("Running Python tests:")
    # 1) Valid small text
    try:
        p = save_uploaded_file(b"hello", "a.txt", "text/plain", MAX_SIZE_BYTES, "uploads_py")
        print("Test 1 OK:", p)
    except Exception as e:
        print("Test 1 FAILED:", e)
    # 2) Suspicious filename
    try:
        p = save_uploaded_file(b"content", "../../evil.txt", "text/plain", MAX_SIZE_BYTES, "uploads_py")
        print("Test 2 OK (sanitized):", p)
    except Exception as e:
        print("Test 2 FAILED:", e)
    # 3) Invalid extension
    try:
        p = save_uploaded_file(b"abc", "run.exe", "application/octet-stream", MAX_SIZE_BYTES, "uploads_py")
        print("Test 3 FAILED (should reject):", p)
    except Exception as e:
        print("Test 3 OK (rejected):", e)
    # 4) Oversize
    try:
        big = b"x" * (MAX_SIZE_BYTES + 1)
        p = save_uploaded_file(big, "big.txt", "text/plain", MAX_SIZE_BYTES, "uploads_py")
        print("Test 4 FAILED (oversize accepted):", p)
    except Exception as e:
        print("Test 4 OK (oversize rejected):", e)
    # 5) Allowed image ext with odd name
    try:
        p = save_uploaded_file(b"\x89PNG", "my image (1).jpg", "image/jpeg", MAX_SIZE_BYTES, "uploads_py")
        print("Test 5 OK:", p)
    except Exception as e:
        print("Test 5 FAILED:", e)

if __name__ == "__main__":
    # Start server
    host, port = "127.0.0.1", 8081
    with socketserver.ThreadingTCPServer((host, port), UploadHandler) as httpd:
        print(f"Python server running on http://{host}:{port}")
        # Run tests
        run_tests()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass