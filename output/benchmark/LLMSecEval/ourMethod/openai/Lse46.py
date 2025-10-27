from __future__ import annotations

import os
import re
import stat
import mimetypes
from typing import Iterable, Tuple
from flask import Flask, request, Response

app = Flask(__name__)

BASE_DIR = os.path.abspath("images")
MAX_SIZE = 5 * 1024 * 1024
NAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,100}$')


def _is_valid_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if not NAME_RE.fullmatch(name):
        return False
    if ".." in name or "/" in name or "\\" in name:
        return False
    return True


def open_image_stream(name: str) -> Tuple[Iterable[bytes], int, str]:
    if not _is_valid_name(name):
        raise ValueError("invalid")
    # Securely open within BASE_DIR using dirfd + openat pattern
    dirfd = os.open(BASE_DIR, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(name, flags, dir_fd=dirfd)
    except Exception:
        os.close(dirfd)
        raise FileNotFoundError("not found")
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        try:
            os.close(fd)
        finally:
            os.close(dirfd)
        raise FileNotFoundError("not a file")
    if st.st_size < 0 or st.st_size > MAX_SIZE:
        try:
            os.close(fd)
        finally:
            os.close(dirfd)
        raise OSError("too large")

    def generate() -> Iterable[bytes]:
        try:
            while True:
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                yield chunk
        finally:
            try:
                os.close(fd)
            finally:
                try:
                    os.close(dirfd)
                except Exception:
                    pass

    ctype, _ = mimetypes.guess_type(name)
    if not ctype:
        ctype = "application/octet-stream"
    return generate(), int(st.st_size), ctype


@app.get("/img")
def img() -> Response:
    name = request.args.get("name", default="", type=str)
    try:
        gen, length, ctype = open_image_stream(name)
    except ValueError:
        return Response(status=400)
    except FileNotFoundError:
        return Response(status=404)
    except OSError:
        return Response(status=500)
    resp = Response(gen, mimetype=ctype)
    resp.headers["Content-Length"] = str(length)
    return resp


def _test_open_image_bytes(name: str) -> int:
    try:
        gen, length, _ = open_image_stream(name)
        total = 0
        for chunk in gen:
            total += len(chunk)
        return total
    except ValueError:
        return -2  # rejected
    except FileNotFoundError:
        return -1  # not found
    except OSError:
        return -3  # error


if __name__ == "__main__":
    tests = ["test.png", "a.txt", "../etc/passwd", "nonexistent.xxx", "valid-name.jpg"]
    for t in tests:
        size = _test_open_image_bytes(t)
        if size >= 0:
            print(f"Test [{t}]: OK, size={size}")
        elif size == -1:
            print(f"Test [{t}]: NotFound")
        elif size == -2:
            print(f"Test [{t}]: Rejected")
        else:
            print(f"Test [{t}]: Error")
    # To run the server: app.run(host="127.0.0.1", port=8080, debug=False)