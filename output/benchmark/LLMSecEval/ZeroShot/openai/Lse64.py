import os
import sys
import errno
import uuid
import shutil
from typing import Optional

try:
    import mysql.connector
except Exception:
    mysql = None  # type: ignore

MAX_SIZE = 10 * 1024 * 1024  # 10 MB
UPLOADS_DIR = "uploads"

class DBConfig:
    def __init__(self, host: str, user: str, password: str, database: str, port: int = 3306):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.port = port

    def get_connection(self):
        if mysql is None:
            raise RuntimeError("mysql.connector is not available")
        return mysql.connector.connect(
            host=self.host, user=self.user, password=self.password,
            database=self.database, port=self.port, auth_plugin='mysql_native_password'
        )

def _ensure_uploads_dir() -> str:
    path = os.path.abspath(UPLOADS_DIR)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return os.path.realpath(path)

def _sanitize_filename(original: Optional[str]) -> str:
    if not original:
        original = "file.pdf"
    name = original.replace("\\", "/").split("/")[-1]
    safe = []
    for ch in name:
        if ch.isalnum() or ch in "._-":
            safe.append(ch)
        else:
            safe.append("_")
    safe_name = "".join(safe)
    if not safe_name.lower().endswith(".pdf"):
        safe_name += ".pdf"
    if len(safe_name) > 100:
        safe_name = safe_name[-100:]
    return safe_name

def _is_valid_pdf(data: bytes) -> bool:
    if not data or len(data) > MAX_SIZE:
        return False
    if not data.startswith(b"%PDF-"):
        return False
    if b"%%EOF" not in data:
        return False
    return True

def _save_filepath_to_db(cfg: Optional[DBConfig], rel_path: str) -> None:
    if cfg is None:
        return
    conn = None
    try:
        conn = cfg.get_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                path VARCHAR(1024) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("INSERT INTO documents (path) VALUES (%s)", (rel_path,))
        conn.commit()
        cur.close()
    finally:
        if conn:
            conn.close()

def upload_pdf(file_bytes: bytes, original_filename: Optional[str], db_config: Optional[DBConfig]) -> str:
    if not _is_valid_pdf(file_bytes):
        raise ValueError("Invalid PDF file")

    uploads_root = _ensure_uploads_dir()
    safe = _sanitize_filename(original_filename)
    base = safe[:-4] if safe.lower().endswith(".pdf") else safe
    attempts = 0
    while True:
        unique = uuid.uuid4().hex
        final_name = f"{base}_{unique}.pdf"
        target = os.path.join(uploads_root, final_name)
        attempts += 1
        if not os.path.exists(target):
            break
        if attempts > 10:
            raise OSError("Failed to allocate unique filename")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(file_bytes)
    finally:
        try:
            os.chmod(target, 0o600)
        except Exception:
            pass

    real_uploads = os.path.realpath(uploads_root)
    real_target = os.path.realpath(target)
    if not real_target.startswith(real_uploads + os.sep) and real_target != real_uploads:
        try:
            os.remove(real_target)
        except Exception:
            pass
        raise PermissionError("Path traversal detected")

    rel_path = os.path.relpath(real_target, real_uploads).replace(os.sep, "/")
    _save_filepath_to_db(db_config, rel_path)
    return rel_path

def download_pdf(stored_path: str) -> bytes:
    uploads_root = _ensure_uploads_dir()
    target = os.path.join(uploads_root, stored_path)
    real_uploads = os.path.realpath(uploads_root)
    real_target = os.path.realpath(target)
    if not real_target.startswith(real_uploads + os.sep) and real_target != real_uploads:
        raise PermissionError("Invalid file path")
    with open(real_target, "rb") as f:
        return f.read()

def _cfg_from_env() -> Optional[DBConfig]:
    host = os.getenv("DB_HOST")
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASS")
    database = os.getenv("DB_NAME")
    port = int(os.getenv("DB_PORT", "3306"))
    if host and user and password and database:
        return DBConfig(host, user, password, database, port)
    return None

if __name__ == "__main__":
    cfg = _cfg_from_env()
    filenames = ["report.pdf", "invoice..pdf", "../../evil.pdf", "résumé.pdf", "noext"]
    pdfs = [f"%PDF-1.4\n% test {i}\n1 0 obj\n<<>>\nendobj\n%%EOF\n".encode("latin1") for i in range(5)]
    stored_paths = []
    for i in range(5):
        try:
            p = upload_pdf(pdfs[i], filenames[i], cfg)
            print(f"Uploaded: {p}")
            stored_paths.append(p)
        except Exception as e:
            print(f"Upload failed {i}: {e}")
            stored_paths.append(None)
    for i in range(5):
        try:
            if stored_paths[i] is None:
                print(f"Skip download {i}")
                continue
            data = download_pdf(stored_paths[i])
            print(f"Download {i} ok={data == pdfs[i]}")
        except Exception as e:
            print(f"Download failed {i}: {e}")