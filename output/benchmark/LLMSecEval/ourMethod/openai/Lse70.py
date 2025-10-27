import os
import sys
import stat
import secrets
import time
from typing import Optional
from flask import Flask, request, Response

app = Flask(__name__)

MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MiB
MAX_FILENAME_LEN = 100

def _sanitize_filename(name: str) -> Optional[str]:
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or len(name) > MAX_FILENAME_LEN:
        return None
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if any(c not in allowed for c in name):
        return None
    if name in (".", ".."):
        return None
    return name

def _ensure_dir(path: str) -> str:
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
    # Normalize and return absolute canonical path (without following symlinks on last component)
    return os.path.realpath(path)

def upload_file(base_dir: str, filename: str, data: bytes) -> str:
    if base_dir is None or filename is None or data is None:
        raise ValueError("Invalid input")
    if len(data) > MAX_UPLOAD_SIZE:
        raise ValueError("File too large")
    base_real = _ensure_dir(base_dir)
    if not os.path.isdir(base_real):
        raise ValueError("Base directory invalid")
    safe = _sanitize_filename(filename)
    if not safe:
        raise ValueError("Invalid filename")
    # Generate unique final name to avoid collisions
    unique_suffix = f"{secrets.token_hex(8)}-{int(time.time()*1000)}"
    final_name = f"{safe}-{unique_suffix}"
    final_path = os.path.join(base_real, final_name)

    # Ensure final path remains within base dir
    normalized_final = os.path.realpath(os.path.join(base_real, final_name))
    if not normalized_final.startswith(base_real + os.sep):
        raise ValueError("Path escapes base directory")

    # Create temp file securely in base directory
    tmp_name = f"tmp-{secrets.token_hex(8)}.upload"
    tmp_path = os.path.join(base_real, tmp_name)

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    # O_NOFOLLOW prevents following symlinks to temp path
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    # O_CLOEXEC for safety
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    fd = None
    try:
        fd = os.open(tmp_path, flags, 0o600)
        # write data with size checks
        total = 0
        view = memoryview(data)
        while total < len(data):
            written = os.write(fd, view[total:total+65536])
            if written <= 0:
                raise OSError("write failed")
            total += written
        os.fsync(fd)
        os.close(fd); fd = None

        # Atomic move to final path
        os.replace(tmp_path, final_path)
        return final_path
    except Exception:
        try:
            if fd is not None:
                os.close(fd)
        except Exception:
            pass
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass
        raise

@app.route("/upload", methods=["POST"])
def http_upload():
    filename = request.headers.get("X-Filename", type=str)
    if not filename:
        return Response("Missing X-Filename header\n", status=400, mimetype="text/plain")
    if request.content_length is None or request.content_length < 0 or request.content_length > MAX_UPLOAD_SIZE:
        return Response("Payload too large or missing Content-Length\n", status=413, mimetype="text/plain")
    try:
        data = request.get_data(cache=False, as_text=False)
        path = upload_file("uploads-py", filename, data)
        return Response(f"Saved: {os.path.basename(path)}\n", status=200, mimetype="text/plain")
    except Exception:
        return Response("Upload failed\n", status=400, mimetype="text/plain")

def _run_tests():
    base = "uploads-py"
    os.makedirs(base, exist_ok=True)
    # Test 1: small text
    try:
        p1 = upload_file(base, "file.txt", b"hello")
        print("Test1 OK:", os.path.basename(p1))
    except Exception:
        print("Test1 FAIL")
    # Test 2: too large
    try:
        big = b"\x00" * (MAX_UPLOAD_SIZE + 1)
        p2 = upload_file(base, "big.bin", big)
        print("Test2 FAIL:", os.path.basename(p2))
    except Exception:
        print("Test2 OK (rejected large)")
    # Test 3: valid name and binary data
    try:
        p3 = upload_file(base, "safe-01.log", b"\x01\x02\x03")
        print("Test3 OK:", os.path.basename(p3))
    except Exception:
        print("Test3 FAIL")
    # Test 4: bad traversal
    try:
        p4 = upload_file(base, "../bad", b"x")
        print("Test4 FAIL:", os.path.basename(p4))
    except Exception:
        print("Test4 OK (rejected bad name)")
    # Test 5: bad chars
    try:
        p5 = upload_file(base, "bad$name.txt", b"data")
        print("Test5 FAIL:", os.path.basename(p5))
    except Exception:
        print("Test5 OK (rejected bad chars)")

if __name__ == "__main__":
    _run_tests()
    os.makedirs("uploads-py", exist_ok=True)
    app.run(host="127.0.0.1", port=5000)