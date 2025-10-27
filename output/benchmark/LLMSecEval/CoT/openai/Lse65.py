import http.server
import socketserver
import sys
import os
import re
import secrets

# Configuration
HOST = "127.0.0.1"
PORT = 8081
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB
UPLOAD_DIR = "uploads"

def set_security_headers(handler):
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
    handler.send_header("Cache-Control", "no-store")

def sanitize_filename(name: str) -> str:
    name = name.replace("\\", "/")
    name = name.split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if name.startswith("."):
        name = "_" + name[1:]
    if not name:
        name = "file.pdf"
    return name

def is_pdf_magic(data: bytes) -> bool:
    i = 0
    while i < len(data) and data[i] in (0x20, 0x09, 0x0D, 0x0A):
        i += 1
    return data[i:i+5] == b"%PDF-"

def ensure_unique(name: str) -> str:
    stem, ext = (name[:-4], name[-4:]) if name.lower().endswith(".pdf") else (name, "")
    candidate = name
    for _ in range(1000):
        if not os.path.exists(os.path.join(UPLOAD_DIR, candidate)):
            return candidate
        candidate = f"{stem}-{secrets.token_hex(3)}{ext}"
    return f"{stem}-{int.from_bytes(secrets.token_bytes(6),'big')}{ext}"

def parse_multipart(body: bytes, boundary: bytes):
    # Returns list of dict: {headers: dict, data: bytes}
    parts = []
    delim = b"--" + boundary
    end_delim = b"--" + boundary + b"--"
    pos = body.find(delim)
    if pos < 0:
        return parts
    pos += len(delim)
    if body[pos:pos+2] == b"\r\n":
        pos += 2
    while True:
        header_end = body.find(b"\r\n\r\n", pos)
        if header_end < 0:
            break
        header_blob = body[pos:header_end].decode("iso-8859-1", errors="replace")
        headers = {}
        for line in header_blob.split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        data_start = header_end + 4
        # look for next boundary
        next_boundary = body.find(b"\r\n--" + boundary, data_start)
        next_close = body.find(b"\r\n" + end_delim, data_start)
        is_last = False
        if next_close != -1 and (next_boundary == -1 or next_close < next_boundary):
            data_end = next_close
            is_last = True
        elif next_boundary != -1:
            data_end = next_boundary
        else:
            # fallback: close without preceding CRLF
            nb = body.find(end_delim, data_start)
            if nb == -1:
                raise ValueError("boundary not found")
            data_end = nb - 2
            is_last = True
        if data_end < data_start:
            data_end = data_start
        data = body[data_start:data_end]
        parts.append({"headers": headers, "data": data})
        if is_last:
            break
        pos = next_boundary + 2 + len(boundary)
        if body[pos:pos+2] == b"\r\n":
            pos += 2
    return parts

class Lse65Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_response(404)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return
        self.send_response(200)
        set_security_headers(self)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html = (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Upload PDF</title></head>"
            "<body><h1>Upload a PDF</h1>"
            "<form method='POST' action='/upload' enctype='multipart/form-data'>"
            "<input type='file' name='file' accept='application/pdf,.pdf' required>"
            "<button type='submit'>Upload</button>"
            "</form></body></html>"
        )
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        if self.path != "/upload":
            self.send_response(404)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype.lower() or "boundary=" not in ctype:
            self.send_response(400)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Bad Request: expected multipart/form-data")
            return
        boundary = None
        for part in ctype.split(";"):
            part = part.strip()
            if part.lower().startswith("boundary="):
                boundary = part.split("=", 1)[1].strip().strip("\"'")
                break
        if not boundary:
            self.send_response(400)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Bad Request: missing boundary")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_UPLOAD_SIZE:
            self.send_response(413 if length > MAX_UPLOAD_SIZE else 400)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Payload Too Large" if length > MAX_UPLOAD_SIZE else b"Bad Request")
            return
        body = self.rfile.read(length)
        try:
            parts = parse_multipart(body, boundary.encode("iso-8859-1"))
        except Exception:
            self.send_response(400)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Bad Request: invalid multipart")
            return

        file_part = None
        filename = None
        for p in parts:
            cd = p["headers"].get("content-disposition", "")
            if "name=\"file\"" in cd and "filename=" in cd:
                # extract filename
                m = re.search(r'filename=(?:"([^"]+)"|\'([^\']+)\'|([^;]+))', cd, re.IGNORECASE)
                if m:
                    filename = next(g for g in m.groups() if g)
                    file_part = p
                    break

        if not file_part or not filename:
            self.send_response(400)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Bad Request: file field missing")
            return

        safe_name = sanitize_filename(filename)
        if not safe_name.lower().endswith(".pdf"):
            self.send_response(415)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Unsupported Media Type: only .pdf allowed")
            return

        data = file_part["data"]
        if not data:
            self.send_response(400)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Bad Request: empty file")
            return

        if not is_pdf_magic(data):
            self.send_response(415)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Unsupported Media Type: invalid PDF signature")
            return

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        unique = ensure_unique(safe_name)
        dest = os.path.join(UPLOAD_DIR, unique)
        try:
            with open(dest, "wb") as f:
                f.write(data)
        except Exception:
            self.send_response(500)
            set_security_headers(self)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Server Error: could not save file")
            return

        self.send_response(200)
        set_security_headers(self)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"Uploaded as: {unique}".encode("utf-8"))

def run_tests():
    print("Running Python tests...")
    # 1) sanitize traversal
    assert ".." not in sanitize_filename("../a.pdf")
    # 2) sanitize hidden
    assert not sanitize_filename(".a.pdf").startswith(".")
    # 3) pdf magic true
    assert is_pdf_magic(b"%PDF-1.7\n...")
    # 4) pdf magic leading whitespace
    assert is_pdf_magic(b"\r\n %PDF-1.4")
    # 5) pdf magic false
    assert not is_pdf_magic(b"not pdf")
    print("All Python tests passed.")

if __name__ == "__main__":
    run_tests()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with socketserver.ThreadingTCPServer((HOST, PORT), Lse65Handler) as httpd:
        print(f"Python server running at http://{HOST}:{PORT}/")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()