import os
import re
import sys
import json
import errno
import stat
from typing import Optional, Dict

MAX_UPLOAD_SIZE = 32 * 1024 * 1024  # 32 MiB

def _sanitize_filename(name: str) -> str:
    base = os.path.basename(name or "")
    base = base.replace("\x00", "_")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if not base.lower().endswith(".pdf"):
        base = re.sub(r"\.[^.]*$", "", base) + ".pdf"
    if len(base) > 100:
        base = base[-100:]
    return base

def _ensure_uploads(base_dir: str) -> str:
    base = os.path.normpath(base_dir)
    if not os.path.exists(base):
        os.makedirs(base, mode=0o700, exist_ok=True)
    if not os.path.isdir(base):
        raise OSError("base dir is not a directory")
    uploads = os.path.normpath(os.path.join(base, "uploads"))
    if not uploads.startswith(base):
        raise OSError("path traversal blocked")
    if not os.path.exists(uploads):
        os.makedirs(uploads, mode=0o700, exist_ok=True)
    if not os.path.isdir(uploads):
        raise OSError("uploads is not a directory")
    if os.path.islink(uploads):
        raise OSError("uploads must not be a symlink")
    return uploads

def _fsync_dir(dir_fd: int) -> None:
    try:
        os.fsync(dir_fd)
    except Exception:
        pass

def _store_path_mysql(db_cfg: Optional[Dict], rel_path: str) -> None:
    if not db_cfg:
        # Fallback: store in mock file so tests run without MySQL
        try:
            base = db_cfg.get("base_dir", ".") if isinstance(db_cfg, dict) else "."
        except Exception:
            base = "."
        idx = os.path.join(base, "mock_mysql_index.json")
        try:
            data = []
            if os.path.exists(idx):
                with open(idx, "r", encoding="utf-8") as f:
                    data = json.load(f)
            data.append({"path": rel_path})
            with open(idx, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass
        return
    try:
        import mysql.connector  # type: ignore
        conn = mysql.connector.connect(
            host=db_cfg.get("host", "127.0.0.1"),
            port=int(db_cfg.get("port", 3306)),
            database=db_cfg.get("database"),
            user=db_cfg.get("user"),
            password=db_cfg.get("password"),
            connection_timeout=5,
            autocommit=True,
        )
        try:
            cur = conn.cursor()
            cur.execute(
                "CREATE TABLE IF NOT EXISTS documents ("
                "id INT AUTO_INCREMENT PRIMARY KEY,"
                "path VARCHAR(1024) NOT NULL)"
            )
            cur.execute("INSERT INTO documents(path) VALUES (%s)", (rel_path,))
            cur.close()
        finally:
            conn.close()
    except Exception:
        # Best-effort only
        pass

def upload_pdf(base_dir: str, original_filename: str, content: bytes, db_cfg: Optional[Dict] = None) -> str:
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("content must be bytes")
    if len(content) == 0:
        raise ValueError("empty content")
    if len(content) > MAX_UPLOAD_SIZE:
        raise ValueError("file too large")
    if not isinstance(original_filename, str) or not original_filename:
        raise ValueError("invalid filename")

    uploads = _ensure_uploads(base_dir)

    safe = _sanitize_filename(original_filename)
    unique = os.urandom(8).hex()
    final_name = f"{unique}_{safe}"
    rel_path = f"uploads/{final_name}"

    # Open base dir and uploads dir securely
    base_fd = os.open(os.path.normpath(base_dir), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        uploads_fd = os.openat(base_fd, "uploads", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        os.close(base_fd)
        raise
    try:
        st_up = os.fstat(uploads_fd)
        if not stat.S_ISDIR(st_up.st_mode):
            raise OSError("uploads not a directory")

        temp_name = f"{final_name}.part_{os.urandom(6).hex()}"
        flags_create = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags_create |= os.O_NOFOLLOW

        fd = os.openat(uploads_fd, temp_name, flags_create, 0o600)
        try:
            written = 0
            mv = memoryview(content)
            while written < len(content):
                n = os.write(fd, mv[written:written + 65536])
                if n <= 0:
                    raise OSError("short write")
                written += n
            os.fsync(fd)
        finally:
            os.close(fd)

        # Atomic replace into final path
        os.rename(
            os.path.join(uploads, temp_name),
            os.path.join(uploads, final_name)
        )

        # Store in MySQL (best-effort)
        if db_cfg is None:
            db_cfg = {"base_dir": base_dir}
        _store_path_mysql(db_cfg, rel_path)
        _fsync_dir(uploads_fd)

        return rel_path
    finally:
        os.close(uploads_fd)
        os.close(base_fd)

def download_pdf(base_dir: str, stored_relative_path: str) -> bytes:
    if not stored_relative_path or stored_relative_path.startswith("/") or ".." in stored_relative_path:
        raise ValueError("invalid stored path")
    if not stored_relative_path.startswith("uploads/"):
        raise ValueError("must be within uploads/")

    base_fd = os.open(os.path.normpath(base_dir), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        uploads_fd = os.openat(base_fd, "uploads", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        os.close(base_fd)
        raise
    try:
        fname = stored_relative_path.split("/", 1)[1]
        flags_read = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags_read |= os.O_NOFOLLOW
        fd = os.openat(uploads_fd, fname, flags_read)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError("not a regular file")
            if st.st_size < 0 or st.st_size > MAX_UPLOAD_SIZE:
                raise OSError("invalid size")
            if st.st_size == 0:
                return b""
            chunks = []
            remaining = st.st_size
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(uploads_fd)
        os.close(base_fd)

def _sample_pdf_bytes(title: str) -> bytes:
    txt = f"""%PDF-1.4
1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj
2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj
3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R>> endobj
4 0 obj <</Length 44>> stream
BT /F1 12 Tf 72 120 Td ({title.replace(')', r'\)')}) Tj ET
endstream endobj
xref
0 5
0000000000 65535 f 
trailer <</Root 1 0 R>>
startxref
0
%%EOF
"""
    return txt.encode("ascii", "strict")

if __name__ == "__main__":
    base = "secure_base_py"
    tests = [
        "report.pdf",
        "../evil.pdf",
        "weird name.PDF",
        "semi;colon.pdf",
        "a/bad/path.pdf",
    ]
    for i, name in enumerate(tests, 1):
        try:
            p = upload_pdf(base, name, _sample_pdf_bytes(f"Test {i}"), db_cfg=None)
            b = download_pdf(base, p)
            print(f"OK: {name} -> {p} size={len(b)}")
        except Exception as e:
            print(f"FAIL: {name} -> {e}")