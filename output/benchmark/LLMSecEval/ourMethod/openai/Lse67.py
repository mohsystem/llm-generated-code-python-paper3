import os
import sys
import stat
from typing import Optional, Tuple
import mysql.connector

MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MiB

def _detect_mime(head: bytes) -> Optional[str]:
    if len(head) >= 8 and head[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    if len(head) >= 3 and head[0] == 0xFF and head[1] == 0xD8 and head[2] == 0xFF:
        return 'image/jpeg'
    if len(head) >= 6 and head[:3] == b'GIF' and head[3] == ord('8') and head[5] == ord('a'):
        return 'image/gif'
    if len(head) >= 2 and head[:2] == b'BM':
        return 'image/bmp'
    if len(head) >= 12 and head[:4] == b'RIFF' and head[8:12] == b'WEBP':
        return 'image/webp'
    return None

def _allowed_extension(path: str, mime: str) -> bool:
    p = path.lower()
    if mime == 'image/png':
        return p.endswith('.png')
    if mime == 'image/jpeg':
        return p.endswith('.jpg') or p.endswith('.jpeg')
    if mime == 'image/gif':
        return p.endswith('.gif')
    if mime == 'image/bmp':
        return p.endswith('.bmp')
    if mime == 'image/webp':
        return p.endswith('.webp')
    return False

def _safe_table_name(name: str) -> bool:
    if not name or len(name) > 64:
        return False
    for ch in name:
        if not (ch.isalnum() or ch == '_'):
            return False
    return True

def _read_image_secure(base_dir: str, relative_path: str) -> Tuple[bytes, str]:
    if not relative_path or os.path.isabs(relative_path):
        raise ValueError("invalid path")

    # Ensure base dir is not a symlink and is a directory
    try:
        st = os.lstat(base_dir)
    except OSError:
        raise ValueError("base directory not accessible")
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError("base directory invalid")
    if stat.S_ISLNK(st.st_mode):
        raise ValueError("base directory must not be a symlink")

    dir_fd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        # Open relative to base directory, do not follow final symlink
        fd = os.open(relative_path, flags, dir_fd=dir_fd, follow_symlinks=False)
        try:
            stf = os.fstat(fd)
            if not stat.S_ISREG(stf.st_mode):
                raise ValueError("not a regular file")
            if stf.st_size <= 0 or stf.st_size > MAX_IMAGE_BYTES:
                raise ValueError("invalid file size")
            # Read contents
            data = b""
            remaining = stf.st_size
            # bound the read in case size changed
            while True:
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_IMAGE_BYTES:
                    raise ValueError("file too large")
            if not data:
                raise ValueError("empty file")
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)

    mime = _detect_mime(data[:max(12, min(len(data), 32))])
    if not mime:
        raise ValueError("unsupported image format")
    if not _allowed_extension(relative_path, mime):
        raise ValueError("extension mismatch")
    return data, mime

def store_image_to_mysql(host: str, port: int, database: str, user: str, password: str,
                         table_name: str, base_dir: str, relative_path: str, name_in_db: str,
                         ssl_ca: Optional[str] = None) -> bool:
    if not (_safe_table_name(table_name) and host and database and user and base_dir and relative_path and name_in_db):
        print("Error: invalid parameters.", file=sys.stderr)
        return False

    try:
        data, mime = _read_image_secure(base_dir, relative_path)
    except Exception:
        print("Error: file validation failed.", file=sys.stderr)
        return False

    # Prepare TLS config; enforce identity verification
    conn_args = {
        "host": host,
        "port": int(port),
        "database": database,
        "user": user,
        "password": password,
        "ssl_disabled": False,
        "ssl_verify_identity": True,
    }
    if ssl_ca:
        conn_args["ssl_ca"] = ssl_ca

    create_sql = f"""
        CREATE TABLE IF NOT EXISTS `{table_name}` (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            mime VARCHAR(64) NOT NULL,
            data LONGBLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci
    """.strip()
    insert_sql = f"INSERT INTO `{table_name}` (name, mime, data) VALUES (%s, %s, %s)"

    try:
        cn = mysql.connector.connect(**conn_args)
        try:
            cn.start_transaction()
            with cn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(insert_sql, (name_in_db, mime, data))
            cn.commit()
        finally:
            cn.close()
        return True
    except Exception:
        print("Error: database operation failed.", file=sys.stderr)
        return False

def _write_file(path: str, data: bytes) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def _minimal_png() -> bytes:
    return bytes([
        0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,
        0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
        0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
        0x08,0x06,0x00,0x00,0x00,0x1F,0x15,0xC4,0x89,
        0x00,0x00,0x00,0x0A,0x49,0x44,0x41,0x54,
        0x78,0x9C,0x63,0x00,0x01,0x00,0x00,0x05,0x00,0x01,
        0x0D,0x0A,0x2D,0xB4,0x00,0x00,0x00,0x00,0x49,0x45,0x4E,0x44,
        0xAE,0x42,0x60,0x82
    ])

def _minimal_jpeg() -> bytes:
    return bytes([
        0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,
        0xFF,0xD9
    ])

if __name__ == "__main__":
    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "3306"))
    db = os.getenv("DB_NAME", "test")
    user = os.getenv("DB_USER", "testuser")
    password = os.getenv("DB_PASS", "testpass")
    table = "images_secure"
    ssl_ca = os.getenv("MYSQL_SSL_CA", None)

    base = os.path.abspath(os.path.join(os.getcwd(), "safe_images_py"))
    if not os.path.exists(base):
        os.makedirs(base, exist_ok=True)

    png = os.path.join(base, "pic1.png")
    jpg = os.path.join(base, "nested", "pic2.jpg")
    bad = os.path.join(base, "note.txt")
    big = os.path.join(base, "big.webp")

    _write_file(png, _minimal_png())
    _write_file(jpg, _minimal_jpeg())
    _write_file(bad, b"hello")
    with open(big, "wb") as f:
        for _ in range(10):
            f.write(b"A" * (1024 * 1024))
        f.write(b"\x00")  # exceed limit

    print("Test1 (valid PNG):", store_image_to_mysql(host, port, db, user, password, table, base, os.path.relpath(png, base), "png_test", ssl_ca))
    print("Test2 (valid JPEG):", store_image_to_mysql(host, port, db, user, password, table, base, os.path.relpath(jpg, base), "jpeg_test", ssl_ca))
    print("Test3 (bad extension):", store_image_to_mysql(host, port, db, user, password, table, base, os.path.relpath(bad, base), "badext_test", ssl_ca))
    print("Test4 (path traversal attempt):", store_image_to_mysql(host, port, db, user, password, table, base, "../etc/passwd", "traversal", ssl_ca))
    print("Test5 (too large):", store_image_to_mysql(host, port, db, user, password, table, base, os.path.relpath(big, base), "big_test", ssl_ca))