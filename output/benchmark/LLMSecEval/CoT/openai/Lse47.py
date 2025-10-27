import os
import re
import mimetypes

# Simple router with decorator
_ROUTES = []

def route(path_pattern: str):
    # Convert /images/<name> to regex
    param_names = []
    regex = "^"
    i = 0
    while i < len(path_pattern):
        c = path_pattern[i]
        if c == '<':
            j = path_pattern.find('>', i + 1)
            if j == -1:
                raise ValueError("Unmatched < in route")
            name = path_pattern[i+1:j].strip()
            param_names.append(name)
            regex += r"([^/]+)"
            i = j + 1
        else:
            if c in r".^$*+?{}[]\|()":
                regex += "\\" + c
            else:
                regex += c
            i += 1
    regex += "$"
    compiled = re.compile(regex)

    def decorator(func):
        _ROUTES.append((compiled, param_names, func))
        return func
    return decorator

def _is_safe_filename(name: str) -> bool:
    if not name or len(name) > 255:
        return False
    if name in (".", ".."):
        return False
    return re.fullmatch(r"[A-Za-z0-9._-]+", name) is not None

def _send_file_if_exists(filename: str):
    images_dir = os.path.abspath("images")
    if not _is_safe_filename(filename):
        return (400, {"Content-Type": "text/plain"}, b"Bad filename")
    target = os.path.abspath(os.path.join(images_dir, filename))
    if not target.startswith(images_dir + os.sep):
        return (400, {"Content-Type": "text/plain"}, b"Invalid path")
    if not (os.path.exists(target) and os.path.isfile(target)):
        return (404, {"Content-Type": "text/plain"}, b"Not Found")
    try:
        with open(target, "rb") as f:
            data = f.read()
        ct = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        headers = {"Content-Type": ct, "Content-Length": str(len(data))}
        return (200, headers, data)
    except Exception:
        return (500, {"Content-Type": "text/plain"}, b"IO Error")

@route("/images/<name>")
def image_handler(name: str):
    return _send_file_if_exists(name)

def serve_request(path: str):
    for regex, params, func in _ROUTES:
        m = regex.match(path)
        if m:
            args = list(m.groups())
            return func(*args)
    return (404, {"Content-Type": "text/plain"}, b"Not Found")

def _write_bytes(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

if __name__ == "__main__":
    # Prepare test files
    os.makedirs("images", exist_ok=True)
    _write_bytes("images/hello.png", b"\x89PNG")
    _write_bytes("images/cat.jpg", b"\xFF\xD8\xFF")
    _write_bytes("images/dots..png", b"\x01\x02\x03\x04")

    tests = [
        "/images/hello.png",      # exists
        "/images/missing.png",    # missing
        "/images/../../secret",   # traversal attempt (blocked by regex anyway)
        "/images/dots..png",      # exists
        "/images/CAT.JPG"         # may not exist depending on FS case-sensitivity
    ]
    for t in tests:
        status, headers, body = serve_request(t)
        print(f"{t} -> status={status}, len={len(body)}")