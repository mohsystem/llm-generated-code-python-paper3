import io
import os
import socketserver
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_UPLOAD_BYTES = 10 * 1024 * 1024

def sanitize_filename(name: str) -> str:
    if not name:
        return "file"
    safe = []
    for ch in name:
        if ch.isalnum() or ch in "._-":
            safe.append(ch)
        else:
            safe.append("_")
    s = "".join(safe)
    while s.startswith("."):
        s = s[1:]
    if not s:
        s = "file"
    if len(s) > 100:
        s = s[:100]
    return s

def upload_file(original_name: str, fileobj, max_bytes: int = MAX_UPLOAD_BYTES) -> str:
    if fileobj is None:
        raise ValueError("No file stream")
    safe_name = sanitize_filename(original_name)
    uploads = os.path.abspath("uploads")
    os.makedirs(uploads, exist_ok=True)

    base, ext = os.path.splitext(safe_name)
    unique = f"{base}-{uuid.uuid4()}{ext}"
    target = os.path.join(uploads, unique)

    total = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(target, flags, 0o600)
    try:
        while True:
            chunk = fileobj.read(8192)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("Uploaded file exceeds size limit")
            os.write(fd, chunk)
        if total == 0:
            raise ValueError("Empty file not allowed")
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            os.remove(target)
        except Exception:
            pass
        raise
    else:
        os.close(fd)
    return target

class UploadHandler(BaseHTTPRequestHandler):
    def _set_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Cache-Control", "no-store")

    def do_POST(self):
        if self.path != "/upload":
            self.send_response(404)
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        filename = self.headers.get("X-Filename")
        if not filename:
            self.send_response(400)
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(b"Missing X-Filename header")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            content_length = -1

        if content_length < 0:
            self.send_response(411)
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(b"Content-Length required")
            return
        if content_length == 0:
            self.send_response(400)
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(b"Empty body")
            return
        if content_length > MAX_UPLOAD_BYTES:
            self.send_response(413)
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(b"Payload too large")
            return

        reader = io.BufferedReader(self.rfile)
        limited = io.BytesIO(reader.read(content_length))
        try:
            saved = upload_file(filename, limited, MAX_UPLOAD_BYTES)
            body = f"Saved: {os.path.abspath(saved)}".encode("utf-8")
            self.send_response(200)
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_response(400)
            self._set_security_headers()
            self.end_headers()
            self.wfile.write(("Upload failed: " + str(e)).encode("utf-8"))

def start_server(port: int = 8081):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), UploadHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd

if __name__ == "__main__":
    start_server(8081)

    print("Running tests for upload_file...")

    # Test 1
    p1 = upload_file("hello.txt", io.BytesIO(b"Hello world"), 1024)
    print("Test 1 saved:", os.path.abspath(p1))

    # Test 2
    p2 = upload_file("../evil.sh", io.BytesIO(b"evil content"), 1024)
    print("Test 2 saved:", os.path.abspath(p2))

    # Test 3
    p3 = upload_file("inv@lid:/name?.bin", io.BytesIO(b"data"), 1024)
    print("Test 3 saved:", os.path.abspath(p3))

    # Test 4
    p4 = upload_file(".bashrc", io.BytesIO(b"bashrc-like"), 1024)
    print("Test 4 saved:", os.path.abspath(p4))

    # Test 5
    try:
        # 2MB with 1MB limit
        big = io.BytesIO(b"\x00" * (2 * 1024 * 1024))
        upload_file("toolarge.dat", big, 1024 * 1024)
        print("Test 5 unexpectedly succeeded")
    except Exception as e:
        print("Test 5 correctly failed:", str(e))

    print("HTTP server listening on http://127.0.0.1:8081/upload")