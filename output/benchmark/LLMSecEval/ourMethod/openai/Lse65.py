import os
import socket
import http.client
import tempfile
import secrets
import string

def upload_pdf_to_localhost(file_path: str, endpoint: str = "/upload", max_size: int = 512 * 1024, port: int = 8000):
    # Enforce loopback only
    host = "127.0.0.1"
    if not isinstance(file_path, str) or not file_path:
        return (-1, "", "Invalid path")
    if not isinstance(endpoint, str) or not endpoint.startswith("/"):
        endpoint = "/upload"
    # Validate extension
    if not file_path.lower().endswith(".pdf"):
        return (-1, "", "Invalid extension")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = -1
    try:
        fd = os.open(file_path, flags)
        st = os.fstat(fd)
        if not (stat_is_regular(st.st_mode)):
            return (-1, "", "Not a regular file")
        if st.st_size <= 0 or st.st_size > max_size:
            return (-1, "", "Invalid size")
        # Read full content safely
        content = b""
        to_read = st.st_size
        while len(content) < to_read:
            chunk = os.read(fd, min(64 * 1024, to_read - len(content)))
            if not chunk:
                break
            content += chunk
        if len(content) != to_read:
            return (-1, "", "Short read")
        # Validate PDF signature
        if len(content) < 5 or content[:5] != b"%PDF-":
            return (-1, "", "Invalid PDF signature")

        boundary = gen_boundary()
        header = build_multipart_header(boundary, safe_filename(os.path.basename(file_path)))
        footer = build_multipart_footer(boundary)
        body = header + content + footer
        # HTTP POST
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.putrequest("POST", endpoint, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", f"{host}:{port}")
        conn.putheader("Connection", "close")
        conn.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        conn.send(body)
        resp = conn.getresponse()
        status = resp.status
        data = resp.read()
        conn.close()
        return (status, data.decode(errors="replace"), "")
    except OSError as e:
        # ELOOP indicates symlink was encountered with O_NOFOLLOW on some systems
        return (-1, "", "Network or IO error")
    finally:
        if fd is not None and fd >= 0:
            try:
                os.close(fd)
            except Exception:
                pass

def stat_is_regular(mode: int) -> bool:
    return (mode & 0o170000) == 0o100000

def gen_boundary() -> str:
    return "----pyboundary" + secrets.token_hex(16)

def build_multipart_header(boundary: str, filename: str) -> bytes:
    lines = [
        f"--{boundary}\r\n",
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n',
        "Content-Type: application/pdf\r\n",
        "\r\n",
    ]
    return "".join(lines).encode("utf-8")

def build_multipart_footer(boundary: str) -> bytes:
    return f"\r\n--{boundary}--\r\n".encode("utf-8")

def safe_filename(name: str) -> str:
    # Minimal sanitization for header context
    return "".join(c if c in string.ascii_letters + string.digits + "._- " else "_" for c in name)

def _create_pdf(path: str, data: bytes):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        total = 0
        while total < len(data):
            w = os.write(fd, data[total: total + 65536])
            if w <= 0:
                raise OSError("short write")
            total += w
        os.fsync(fd)
    finally:
        os.close(fd)

if __name__ == "__main__":
    tmpdir = tempfile.mkdtemp(prefix="py_pdfup_")
    max_size = 512 * 1024
    try:
        minimal_pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
        # 1) valid
        f1 = os.path.join(tmpdir, "t1.pdf")
        _create_pdf(f1, minimal_pdf)
        # 2) valid
        f2 = os.path.join(tmpdir, "t2.pdf")
        _create_pdf(f2, minimal_pdf)
        # 3) invalid extension
        f3 = os.path.join(tmpdir, "notes.txt")
        _create_pdf(f3, minimal_pdf)
        # 4) invalid header but .pdf
        f4 = os.path.join(tmpdir, "bad.pdf")
        _create_pdf(f4, b"HELLO WORLD")
        # 5) oversized
        big = bytearray(b"%PDF-1.4\n")
        chunk = b"A" * (64 * 1024)
        repeats = (max_size // len(chunk)) + 2
        for _ in range(repeats):
            big += chunk
        big += b"%%EOF\n"
        f5 = os.path.join(tmpdir, "big.pdf")
        _create_pdf(f5, bytes(big))

        tests = [f1, f2, f3, f4, f5]
        for i, path in enumerate(tests, 1):
            status, body, err = upload_pdf_to_localhost(path, "/upload", max_size=max_size, port=8000)
            print(f"Test{i}: status={status}, err='{err}', body_len={len(body)}")
    finally:
        try:
            for name in os.listdir(tmpdir):
                try: os.unlink(os.path.join(tmpdir, name))
                except Exception: pass
            os.rmdir(tmpdir)
        except Exception:
            pass