# Python implementation
# Chain-of-Through process (brief in-code annotations only):
# 1) Problem: store image file into MySQL as BLOB.
# 2) Security: validate table, parameterized queries, size limits, safe error handling.
# 3) Secure coding: use mysql.connector with prepared statements, avoid hardcoded secrets, resource cleanup.
# 4) Review: check for SQLi, large files, and exceptions.
# 5) Output: final secure function with tests.

import os
import re
import mimetypes
import tempfile

try:
    import mysql.connector  # Requires mysql-connector-python
except Exception:
    mysql = None  # For environments without the connector


MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

def _safe_identifier(name: str) -> bool:
    return isinstance(name, str) and 1 <= len(name) <= 64 and re.fullmatch(r"[A-Za-z0-9_]+", name) is not None

def _detect_mime(path: str) -> str:
    mime, _ = mimetypes.guess_type(path)
    return mime or "application/octet-stream"

def store_image_to_mysql(host: str, port: int, user: str, password: str, database: str, table: str, record_id: str, file_path: str) -> bool:
    if mysql is None:
        return False
    if not _safe_identifier(table):
        return False
    if not record_id or not isinstance(record_id, str):
        return False
    if not os.path.isfile(file_path):
        return False
    size = os.path.getsize(file_path)
    if size <= 0 or size > MAX_FILE_SIZE_BYTES:
        return False

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        filename = os.path.basename(file_path)
        mime = _detect_mime(file_path)

        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            connection_timeout=8,
            autocommit=False,
        )
        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS `{table}` ("
                    "id VARCHAR(128) PRIMARY KEY,"
                    "filename VARCHAR(255) NOT NULL,"
                    "mime_type VARCHAR(100) NOT NULL,"
                    "size_bytes BIGINT NOT NULL,"
                    "data LONGBLOB NOT NULL)"
                )
                cur.execute(
                    f"REPLACE INTO `{table}` (id, filename, mime_type, size_bytes, data) VALUES (%s, %s, %s, %s, %s)",
                    (record_id, filename, mime, len(data), data),
                )
                conn.commit()
                return True
            except Exception:
                conn.rollback()
                return False
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception:
        return False

# 5 test cases in main
if __name__ == "__main__":
    def tiny_png_bytes():
        return bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0x00,0x00,0x00,0x00,0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82])

    def temp_image(suffix: str) -> str:
        fd, path = tempfile.mkstemp(suffix=suffix, prefix="imgpy_")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(tiny_png_bytes())
        return path

    host = os.getenv("DB_HOST", "127.0.0.1")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASS", "password")
    database = os.getenv("DB_NAME", "test")
    table = os.getenv("DB_TABLE", "images_secure_py")

    p1 = temp_image(".png")
    p2 = temp_image(".jpg")
    p3 = temp_image(".gif")
    p4 = temp_image(".webp")
    p5 = temp_image(".bmp")

    store_image_to_mysql(host, port, user, password, database, table, "py_img1", p1)
    store_image_to_mysql(host, port, user, password, database, table, "py_img2", p2)
    store_image_to_mysql(host, port, user, password, database, table, "py_img3", p3)
    store_image_to_mysql(host, port, user, password, database, table, "py_img4", p4)
    store_image_to_mysql(host, port, user, password, database, table, "py_img5", p5)

    for p in (p1, p2, p3, p4, p5):
        try:
            os.remove(p)
        except Exception:
            pass