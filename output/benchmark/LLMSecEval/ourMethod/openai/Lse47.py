from __future__ import annotations
import os
import stat
import mimetypes
import posixpath
import urllib.parse
from flask import Flask, Response, request

app = Flask(__name__)

MAX_SIZE = 1 * 1024 * 1024  # 1 MiB
BASE_IMAGES_DIR = os.path.join(os.getcwd(), "images")

def _validate_rel_path(rel: str) -> str | None:
    if not isinstance(rel, str):
        return None
    if len(rel) == 0 or len(rel) > 4096:
        return None
    # Decode percent-encoding
    rel = urllib.parse.unquote(rel)
    # Normalize to POSIX form
    rel = rel.replace("\\", "/")
    rel = posixpath.normpath(rel)
    if rel.startswith("/") or rel.startswith("../") or rel == ".." or "\x00" in rel:
        return None
    # Reject empty or directory traversal
    parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
    if not parts:
        return None
    safe = "/".join(parts)
    return safe

def _open_image_secure(relpath: str):
    safe_rel = _validate_rel_path(relpath)
    if safe_rel is None:
        return 400, "Invalid path", None, None

    try:
        # Open base directory
        dirfd = os.open(BASE_IMAGES_DIR, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return 500, "Server error", None, None

    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        # Avoid following symlinks if available
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(safe_rel, flags, dir_fd=dirfd)
        st = os.fstat(fd)
        # Ensure regular file and within size policy
        if not stat.S_ISREG(st.st_mode):
            return 404, "Not Found", None, None
        if st.st_size < 0 or st.st_size > MAX_SIZE:
            return 413, "Payload Too Large", None, None

        # Content type
        ctype, _ = mimetypes.guess_type(safe_rel)
        if not ctype:
            ctype = "application/octet-stream"

        f = os.fdopen(fd, "rb", closefd=True)
        fd = -1  # handed off to file object
        def generate():
            with f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    yield chunk

        headers = {"Content-Type": ctype, "Content-Length": str(st.st_size)}
        return 200, None, headers, generate()
    except OSError as e:
        # ELOOP -> symlink encountered
        return 404, "Not Found", None, None
    finally:
        try:
            os.close(dirfd)
        except Exception:
            pass
        if fd != -1:
            try:
                os.close(fd)
            except Exception:
                pass

@app.route("/images/<path:req_path>", methods=["GET"])
def serve_image(req_path: str):
    code, msg, headers, body_iter = _open_image_secure(req_path)
    if code != 200:
        return Response(msg, status=code, content_type="text/plain; charset=utf-8")
    resp = Response(body_iter, status=200)
    for k, v in headers.items():
        resp.headers[k] = v
    return resp

@app.route("/images", methods=["GET"])
def images_root():
    return Response("Missing filename", status=400, content_type="text/plain; charset=utf-8")

if __name__ == "__main__":
    # Setup test environment
    os.makedirs(BASE_IMAGES_DIR, exist_ok=True)
    # Test files
    with open(os.path.join(BASE_IMAGES_DIR, "hello.txt"), "wb") as f:
        f.write(b"Hello World!")
    # Large file just over limit
    with open(os.path.join(BASE_IMAGES_DIR, "big.bin"), "wb") as f:
        f.write(bytes([i & 0xFF for i in range(MAX_SIZE + 1)]))
    # Outside file and symlink
    outside_path = os.path.join(os.getcwd(), "outside.txt")
    with open(outside_path, "wb") as f:
        f.write(b"outside")
    link_path = os.path.join(BASE_IMAGES_DIR, "link_to_outside.txt")
    try:
        if os.path.lexists(link_path):
            os.remove(link_path)
        os.symlink(os.path.join("..", "outside.txt"), link_path)
    except Exception:
        pass  # symlink may not be supported

    # 5 test cases using Flask test client
    client = app.test_client()

    tests = [
        "/images/hello.txt",               # 200
        "/images/missing.txt",             # 404
        "/images/../outside.txt",          # 400
        "/images/link_to_outside.txt",     # 404 (symlink not followed)
        "/images/big.bin",                 # 413
    ]
    for t in tests:
        resp = client.get(t)
        print(f"{t} -> {resp.status_code}")