import http.server
import socketserver
import threading
import urllib.parse
import os
import sys
import time
import secrets
import socket

MAX_SIZE = 10 * 1024 * 1024  # 10MB
HOST = "127.0.0.1"
PORT = 8081

def sanitize_name(name: str):
    if name is None:
        return None
    if len(name) < 1 or len(name) > 100:
        return None
    if name.startswith(".") or ".." in name:
        return None
    for ch in name:
        if not (ch.isalnum() or ch in "._-"):
            return None
    return name

def ensure_upload_dir():
    base = "uploads"
    os.makedirs(base, mode=0o700, exist_ok=True)
    # Open directory securely
    dirfd = os.open(base, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        st = os.fstat(dirfd)
        if not stat_is_dir(st.st_mode):
            os.close(dirfd)
            raise OSError("upload base is not a directory")
    except Exception:
        os.close(dirfd)
        raise
    return dirfd, base

def stat_is_dir(mode):
    return (mode & 0o170000) == 0o040000

def gen_stored_name(base_name: str):
    ext = ""
    if "." in base_name:
        prefix, maybe_ext = base_name.rsplit(".", 1)
        if 1 <= len(maybe_ext) <= 10 and maybe_ext.isalnum():
            ext = "." + maybe_ext
            base = prefix
        else:
            base = base_name
    else:
        base = base_name
    return f"{base}-{int(time.time()*1000)}-{secrets.token_hex(4)}{ext}"

class UploadHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SecureUpload/1.0"

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/upload":
            self.send_error(404)
            return
        params = urllib.parse.parse_qs(parsed.query or "")
        name = params.get("name", [None])[0]
        safe = sanitize_name(name)
        if not safe:
            self.send_error(400, "Bad Request")
            return

        cl = self.headers.get("Content-Length")
        if cl is None:
            self.send_error(411, "Length Required")
            return
        try:
            length = int(cl)
        except Exception:
            self.send_error(400, "Bad Request")
            return
        if length < 0 or length > MAX_SIZE:
            self.send_error(413, "Payload Too Large")
            return

        try:
            dirfd, base = ensure_upload_dir()
        except Exception:
            self.send_error(500, "Internal Server Error")
            return

        stored = gen_stored_name(safe)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        # O_NOFOLLOW may not exist on some platforms
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC

        fd = -1
        try:
            fd = os.open(stored, flags, 0o600, dir_fd=dirfd)
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(8192, remaining))
                if not chunk:
                    break
                os.write(fd, chunk)
                remaining -= len(chunk)

            if remaining != 0:
                try:
                    os.close(fd)
                except Exception:
                    pass
                try:
                    os.unlink(stored, dir_fd=dirfd)
                except Exception:
                    pass
                self.send_error(400, "Bad Request")
                return

            os.fsync(fd)
            os.close(fd)
            fd = -1
            # fsync directory
            try:
                os.fsync(dirfd)
            except Exception:
                pass

            body = ('{"stored":"%s"}\n' % stored).encode("utf-8")
            self.send_response(201, "Created")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileExistsError:
            self.send_error(409, "Conflict")
        except PermissionError:
            self.send_error(403, "Forbidden")
        except OSError:
            self.send_error(500, "Internal Server Error")
        finally:
            if fd != -1:
                try:
                    os.close(fd)
                except Exception:
                    pass
            try:
                os.close(dirfd)
            except Exception:
                pass

    def log_message(self, fmt, *args):
        # Quiet default logging
        return

def run_server():
    httpd = socketserver.TCPServer((HOST, PORT), UploadHandler, bind_and_activate=False)
    # Allow quick restart
    httpd.allow_reuse_address = True
    httpd.server_bind()
    httpd.server_activate()
    return httpd

def http_post(name: str, data: bytes) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    req = []
    path = f"/upload?name={urllib.parse.quote(name)}"
    req.append(f"POST {path} HTTP/1.1")
    req.append(f"Host: {HOST}:{PORT}")
    req.append("Content-Type: application/octet-stream")
    req.append(f"Content-Length: {len(data)}")
    req.append("Connection: close")
    req.append("")  # empty line
    head = ("\r\n".join(req) + "\r\n").encode("ascii")
    s.sendall(head + data)
    # read status line
    f = s.makefile("rb")
    status = f.readline().decode("iso-8859-1")
    code = 0
    if status.startswith("HTTP/"):
        parts = status.split()
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
    # consume rest
    while f.read(8192):
        pass
    f.close()
    s.close()
    return code

def main():
    httpd = run_server()
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    ok = 0
    try:
        # 1) Small valid upload
        ok += 1 if http_post("hello.txt", b"Hello") == 201 else 0
        # 2) Invalid name (traversal)
        ok += 1 if http_post("../evil", b"data") == 400 else 0
        # 3) Empty file
        ok += 1 if http_post("empty.bin", b"") == 201 else 0
        # 4) Too large
        ok += 1 if http_post("big.bin", b"x" * (MAX_SIZE + 1)) == 413 else 0
        # 5) Another valid upload
        ok += 1 if http_post("rand.dat", os.urandom(1024)) == 201 else 0
    finally:
        httpd.shutdown()
        httpd.server_close()
    print(f"Tests passed: {ok}/5")

if __name__ == "__main__":
    main()