import http.server
import socketserver
import threading
import urllib.request
import os
import time

class Lse71:
    @staticmethod
    def build_multipart_body(boundary: str, field_name: str, filename: str, content: bytes) -> bytes:
        parts = []
        parts.append(f"--{boundary}\r\n".encode("latin-1"))
        parts.append(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("latin-1"))
        parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
        parts.append(content)
        parts.append(b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode("latin-1"))
        return b"".join(parts)

    @staticmethod
    def save_uploaded_file(body: bytes, content_type: str, upload_dir: str) -> str:
        if content_type is None or "multipart/form-data" not in content_type:
            raise ValueError("Invalid Content-Type")
        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.lower().startswith("boundary="):
                boundary = part.split("=", 1)[1].strip()
                if boundary.startswith('"') and boundary.endswith('"'):
                    boundary = boundary[1:-1]
                break
        if not boundary:
            raise ValueError("Boundary not found")

        data = body.decode("latin-1", errors="ignore")
        boundary_marker = "--" + boundary
        pos = 0
        while True:
            part_start = data.find(boundary_marker, pos)
            if part_start == -1:
                break
            part_start += len(boundary_marker)
            if data.startswith("--", part_start):
                break
            if not data.startswith("\r\n", part_start):
                break
            headers_start = part_start + 2
            headers_end = data.find("\r\n\r\n", headers_start)
            if headers_end == -1:
                break
            headers_block = data[headers_start:headers_end]
            headers = {}
            for line in headers_block.split("\r\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            cd = headers.get("content-disposition", "")
            if "form-data" in cd:
                filename = None
                for token in cd.split(";"):
                    token = token.strip()
                    if token.lower().startswith("filename="):
                        filename = token.split("=", 1)[1].strip()
                        if filename.startswith('"') and filename.endswith('"'):
                            filename = filename[1:-1]
                        break
                content_start = headers_end + 4
                boundary_delim = "\r\n" + boundary_marker
                content_end = data.find(boundary_delim, content_start)
                if content_end == -1:
                    content_end = len(data)
                if filename:
                    safe = filename.replace("\\", "/")
                    safe = os.path.basename(safe)
                    if not safe:
                        safe = "upload.bin"
                    os.makedirs(upload_dir, exist_ok=True)
                    path = os.path.join(upload_dir, safe)
                    base, ext = os.path.splitext(path)
                    counter = 1
                    while os.path.exists(path):
                        path = f"{base}_{counter}{ext}"
                        counter += 1
                    file_bytes = body[content_start:content_end]
                    with open(path, "wb") as f:
                        f.write(file_bytes)
                    return os.path.abspath(path)
            pos = headers_end + 4
        raise ValueError("No file part found")

    class Handler(http.server.BaseHTTPRequestHandler):
        upload_dir = "uploads_py"

        def do_GET(self):
            html = """<!doctype html><html><body>
<h3>Upload File (Python)</h3>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" />
<button type="submit">Upload</button>
</form></body></html>"""
            data = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            ctype = self.headers.get("Content-Type")
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            try:
                saved = Lse71.save_uploaded_file(body, ctype, self.upload_dir)
                resp = f"Uploaded to: {saved}".encode("utf-8")
                self.send_response(200)
            except Exception as e:
                resp = f"Upload failed: {e}".encode("utf-8")
                self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

    @staticmethod
    def start_server(port: int, upload_dir: str):
        handler = Lse71.Handler
        handler.upload_dir = upload_dir
        httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd

    @staticmethod
    def upload_test(url: str, filename: str, content: bytes) -> int:
        boundary = "----LSE71PYBOUNDARY" + str(time.time_ns())
        body = Lse71.build_multipart_body(boundary, "file", filename, content)
        req = urllib.request.Request(url, method="POST", data=body)
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        req.add_header("Content-Length", str(len(body)))
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
                return resp.getcode()
        except urllib.error.HTTPError as e:
            if e.fp:
                e.fp.read()
            return e.code
        except Exception:
            return 0

if __name__ == "__main__":
    server = Lse71.start_server(8081, "uploads_py")
    time.sleep(0.3)
    tests = [
        ("py_test1.txt", b"Hello from Python 1"),
        ("py_test2.txt", b"Second content\nLine 2"),
        ("py_test3.bin", bytes([0,1,2,3,4,255])),
        ("py_test4.txt", b""),
        ("py_test5_utf8.txt", "最后一个测试".encode("utf-8")),
    ]
    for name, content in tests:
        code = Lse71.upload_test("http://localhost:8081/", name, content)
        # print("Upload", name, "->", code)
    # server.serve_forever()  # keeps running