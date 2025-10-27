import os
import re
import sys
import time
import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB
UPLOADS_DIR = Path("uploads")

def ensure_uploads_dir_secure():
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(UPLOADS_DIR, 0o700)
    except Exception:
        pass

def sanitize_filename(original: str) -> str:
    if not original:
        return "upload.pdf"
    base = original.replace("\\", "/")
    base = base.split("/")[-1]
    base = re.sub(r"[\x00-\x1F\x7F]", "", base)
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if not base.lower().endswith(".pdf"):
        base = base + ".pdf"
    if len(base) > 100:
        base = base[:96] + ".pdf"
    if base == ".pdf":
        base = "upload.pdf"
    return base

def is_likely_pdf(data: bytes) -> bool:
    return isinstance(data, (bytes, bytearray)) and len(data) >= 5 and data[:5] == b"%PDF-"

def save_pdf_securely(original_filename: str, data: bytes) -> Path:
    if not is_likely_pdf(data):
        raise ValueError("Not a PDF")
    safe = sanitize_filename(original_filename)
    target = (UPLOADS_DIR / safe).resolve()
    if UPLOADS_DIR.resolve() not in target.parents and target != UPLOADS_DIR.resolve():
        raise PermissionError("Invalid path")
    if target.exists():
        stem, ext = os.path.splitext(safe)
        counter = 1
        while True:
            cand = UPLOADS_DIR / f"{stem}-{counter}{ext}"
            if not cand.exists():
                target = cand
                break
            counter += 1
    with open(target, "wb") as f:
        f.write(data)
    try:
        os.chmod(target, 0o600)
    except Exception:
        pass
    return target

def parse_boundary(content_type: str):
    if not content_type:
        return None
    parts = [p.strip() for p in content_type.split(";")]
    for p in parts:
        if p.lower().startswith("boundary="):
            b = p[9:]
            if b.startswith('"') and b.endswith('"') and len(b) >= 2:
                b = b[1:-1]
            return b.encode("iso-8859-1")
    return None

def read_request_body_limited(rfile, content_length: int, max_size: int) -> bytes:
    if content_length is None or content_length < 0 or content_length > max_size:
        raise ValueError("Invalid content-length")
    buf = bytearray()
    remaining = content_length
    chunk = 8192
    while remaining > 0:
        to_read = min(chunk, remaining)
        data = rfile.read(to_read)
        if not data:
            break
        buf += data
        remaining -= len(data)
        if len(buf) > max_size:
            raise ValueError("Too large")
    if remaining != 0:
        raise ValueError("Unexpected EOF")
    return bytes(buf)

def parse_multipart_single_file(body: bytes, boundary: bytes):
    if not boundary:
        raise ValueError("Missing boundary")
    dash_boundary = b"--" + boundary
    if body.find(dash_boundary) == -1:
        raise ValueError("Boundary not found")
    # Find headers start
    pos = body.find(b"Content-Disposition")
    if pos == -1:
        raise ValueError("No content-disposition")
    headers_end = body.find(b"\r\n\r\n", pos)
    if headers_end == -1:
        raise ValueError("Malformed headers")
    headers = body[pos:headers_end].decode("iso-8859-1", errors="ignore")
    if "form-data" not in headers or 'name="file"' not in headers:
        raise ValueError("Expected field 'file'")
    filename = None
    m = re.search(r'filename="([^"]*)"', headers, flags=re.IGNORECASE)
    if m:
        filename = m.group(1)
    if not filename:
        raise ValueError("Missing filename")
    content_start = headers_end + 4
    # Find next boundary
    next_b = body.find(b"\r\n--" + boundary, content_start)
    if next_b == -1:
        next_b = body.find(b"--" + boundary + b"--", content_start)
        if next_b == -1:
            raise ValueError("Ending boundary not found")
    content = body[content_start:next_b]
    # Trim trailing CRLF
    while content.endswith(b"\r") or content.endswith(b"\n"):
        content = content[:-1]
    # Guess part content-type
    ctype_match = re.search(r'Content-Type:\s*([^\r\n]+)', headers, flags=re.IGNORECASE)
    part_ctype = ctype_match.group(1).strip() if ctype_match else None
    return filename, part_ctype, content

class SecureUploadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Upload PDF</title></head>"
            "<body><h1>Upload PDF</h1>"
            "<form method='POST' action='/upload' enctype='multipart/form-data'>"
            "<input type='file' name='file' accept='application/pdf' required>"
            "<button type='submit'>Upload</button>"
            "</form></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):
        if self.path != "/upload":
            self.send_error(404)
            return
        content_type = self.headers.get("Content-Type")
        boundary = parse_boundary(content_type)
        try:
            cl = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self.send_error(411, "Missing or invalid Content-Length")
            return
        try:
            body = read_request_body_limited(self.rfile, cl, MAX_UPLOAD_SIZE)
        except Exception:
            self.send_error(413, "Upload too large or invalid")
            return
        try:
            filename, part_ctype, content = parse_multipart_single_file(body, boundary)
        except Exception:
            self.send_error(400, "Malformed multipart/form-data")
            return
        if not part_ctype or not part_ctype.lower().startswith("application/pdf"):
            self.send_error(415, "Only application/pdf allowed")
            return
        if not is_likely_pdf(content):
            self.send_error(415, "Invalid PDF content")
            return
        try:
            ensure_uploads_dir_secure()
            saved = save_pdf_securely(filename, content)
        except Exception:
            self.send_error(500, "Failed to save file")
            return
        msg = f"Uploaded to: {saved.resolve()}"
        data = msg.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers        ()
        self.wfile.write(data)

def start_server(port: int):
    ensure_uploads_dir_secure()
    httpd = HTTPServer(("127.0.0.1", port), SecureUploadHandler)
    print(f"Python server started at http://127.0.0.1:{port} (uploads -> {UPLOADS_DIR.resolve()})")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()

def main():
    # 5 tests
    print("Test1:", sanitize_filename("../../etc/passwd"))
    print("Test2:", is_likely_pdf(b"%PDF-1.5\n"))
    print("Test3:", is_likely_pdf(b"NotAPDF"))
    print("Test4:", sanitize_filename("report.txt"))
    ensure_uploads_dir_secure()
    p1 = save_pdf_securely("sample.pdf", b"%PDF-1.4\n%test\n")
    p2 = save_pdf_securely("sample.pdf", b"%PDF-1.4\n%test\n")
    print("Test5:", p1.name, "|", p2.name)
    port = 8081
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    start_server(port)

if __name__ == "__main__":
    main()