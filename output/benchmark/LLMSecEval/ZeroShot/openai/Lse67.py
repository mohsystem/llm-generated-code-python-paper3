import os
import sys
import hashlib
import mysql.connector

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
TABLE_NAME = "images"

def _detect_image_mime(head: bytes, file_name: str) -> str | None:
    if len(head) >= 8 and head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if len(head) >= 3 and head[0:3] == b"\xFF\xD8\xFF":
        return "image/jpeg"
    if len(head) >= 6 and (head[:6] == b"GIF87a" or head[:6] == b"GIF89a"):
        return "image/gif"
    if len(head) >= 12 and head[0:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if len(head) >= 2 and head[:2] == b"BM":
        return "image/bmp"
    if len(head) >= 4 and (head[:4] == b"II*\x00" or head[:4] == b"MM\x00*"):
        return "image/tiff"
    # Fallback only if extension strongly suggests image
    ext = os.path.splitext(file_name)[1].lower()
    if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"):
        return {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".bmp": "image/bmp",
            ".tif": "image/tiff",
            ".tiff": "image/tiff",
            ".webp": "image/webp",
        }[ext]
    return None

def _ensure_table_exists(conn):
    ddl = f"""
    CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
        id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        mime_type VARCHAR(100) NOT NULL,
        data LONGBLOB NOT NULL,
        sha256 CHAR(64) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_sha256 (sha256)
    ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    """
    cur = conn.cursor()
    cur.execute(ddl)
    cur.close()

def store_image_to_db(host: str, port: int, database: str, user: str, password: str, image_path: str) -> int:
    path = os.path.abspath(image_path)
    if not os.path.isfile(path):
        raise ValueError(f"File not found or not a regular file: {path}")
    size = os.path.getsize(path)
    if size <= 0 or size > MAX_FILE_SIZE:
        raise ValueError(f"Invalid file size. Must be > 0 and <= {MAX_FILE_SIZE} bytes")

    with open(path, "rb") as f:
        head = f.read(64)
        mime = _detect_image_mime(head, os.path.basename(path))
        if not mime:
            raise ValueError("Unsupported or unrecognized image format")
        f.seek(0)
        data = f.read()

    sha256 = hashlib.sha256(data).hexdigest()

    conn = mysql.connector.connect(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        connection_timeout=10,
        auth_plugin='mysql_native_password'
    )
    try:
        conn.start_transaction()
        _ensure_table_exists(conn)
        sql = f"INSERT INTO {TABLE_NAME} (name, mime_type, data, sha256) VALUES (%s, %s, %s, %s)"
        cur = conn.cursor()
        cur.execute(sql, (os.path.basename(path), mime, data, sha256))
        if cur.rowcount != 1:
            conn.rollback()
            raise RuntimeError("Insert failed")
        conn.commit()
        inserted_id = cur.lastrowid
        cur.close()
        return inserted_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    host = os.getenv("DB_HOST", "127.0.0.1")
    port = int(os.getenv("DB_PORT", "3306"))
    database = os.getenv("DB_NAME", "test")
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASS", "")

    tests = [
        "sample1.jpg",
        "sample2.png",
        "not_found_image.bin",
        "test.txt",
        "small.gif"
    ]

    for i, fp in enumerate(tests, 1):
        try:
            new_id = store_image_to_db(host, port, database, user, password, fp)
            print(f"Test {i}: Inserted ID = {new_id} for file {fp}")
        except Exception as e:
            print(f"Test {i}: Failed for file {fp} -> {e}", file=sys.stderr)