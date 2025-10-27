# Chain-of-Through process:
# 1) Problem understanding: Save uploaded PDF to "uploads", store filepath in MySQL, later use filepath to download.
# 2) Security requirements: validate PDF signature and size, sanitize filename, prevent traversal, use parameterized SQL, set restrictive perms.
# 3) Secure coding generation implemented below.
# 4) Code review addressed via comments and safeguards.
# 5) Secure code output.

import os
import sys
import time
import base64
import errno
import secrets
from pathlib import Path
from typing import Optional, Dict, Any

class Lse64:
    UPLOAD_DIR = Path("uploads").resolve()
    MAX_BYTES = 10 * 1024 * 1024  # 10 MiB
    _memory_db = []  # fallback when MySQL unavailable

    @staticmethod
    def _ensure_uploads_dir() -> None:
        Lse64.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        # Restrictive permissions where possible (POSIX)
        try:
            os.chmod(Lse64.UPLOAD_DIR, 0o700)
        except Exception:
            pass

    @staticmethod
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
        out = "".join(safe)
        if not out.lower().endswith(".pdf"):
            out += ".pdf"
        if out in (".pdf", "_", ""):
            out = "file.pdf"
        return out

    @staticmethod
    def _unique_filename(base: str) -> str:
        stem, sep, ext = base.rpartition(".")
        if not sep:  # no dot
            stem, ext = base, "pdf"
        if len(stem) > 64:
            stem = stem[:64]
        ts = str(int(time.time() * 1000))
        rand = base64.urlsafe_b64encode(secrets.token_bytes(6)).decode().rstrip("=")
        return f"{stem}_{ts}_{rand}.{ext}"

    @staticmethod
    def _is_pdf(data: bytes) -> bool:
        if not isinstance(data, (bytes, bytearray)):
            return False
        if len(data) < 5 or len(data) > Lse64.MAX_BYTES:
            return False
        return data[:5] == b"%PDF-"

    @staticmethod
    def _safe_resolve(filename: str) -> Path:
        p = (Lse64.UPLOAD_DIR / filename).resolve()
        if not str(p).startswith(str(Lse64.UPLOAD_DIR)):
            raise PermissionError("Invalid path (path traversal detected)")
        return p

    @staticmethod
    def _write_secure_file(target: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(str(target), flags, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
        except FileExistsError:
            raise FileExistsError("Target already exists unexpectedly")

    @staticmethod
    def _mysql_connect(cfg: Optional[Dict[str, Any]]):
        if not cfg:
            return None
        try:
            import mysql.connector  # type: ignore
            conn = mysql.connector.connect(
                host=cfg.get("host", "localhost"),
                port=cfg.get("port", 3306),
                user=cfg.get("user"),
                password=cfg.get("password"),
                database=cfg.get("database"),
                autocommit=True,
                use_pure=True,
                ssl_disabled=False
            )
            return conn
        except Exception:
            return None

    @staticmethod
    def _ensure_table(conn) -> None:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS uploads ("
            "id BIGINT PRIMARY KEY AUTO_INCREMENT,"
            "filepath VARCHAR(1024) NOT NULL)"
        )
        cur.close()

    @staticmethod
    def _insert_filepath(conn, filepath: str) -> int:
        Lse64._ensure_table(conn)
        cur = conn.cursor()
        cur.execute("INSERT INTO uploads (filepath) VALUES (%s)", (filepath,))
        try:
            inserted_id = int(getattr(cur, "lastrowid", 0) or 0)
        except Exception:
            inserted_id = 0
        cur.close()
        return inserted_id

    @staticmethod
    def upload_pdf(pdf_bytes: bytes, original_filename: str, mysql_config: Optional[Dict[str, Any]] = None) -> str:
        if not Lse64._is_pdf(pdf_bytes):
            raise ValueError("Invalid PDF or size exceeds limit")

        Lse64._ensure_uploads_dir()
        safe = Lse64._sanitize_filename(original_filename)
        unique = Lse64._unique_filename(safe)
        target = Lse64._safe_resolve(unique)
        Lse64._write_secure_file(target, pdf_bytes)

        stored_path = str(target)
        conn = Lse64._mysql_connect(mysql_config)
        if conn is not None:
            try:
                inserted_id = Lse64._insert_filepath(conn, stored_path)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        else:
            Lse64._memory_db.append(stored_path)
        return stored_path

    @staticmethod
    def download_pdf(filepath: str) -> bytes:
        if not filepath or not isinstance(filepath, str):
            raise ValueError("Invalid filepath")
        p = Path(filepath).resolve()
        if not str(p).startswith(str(Lse64.UPLOAD_DIR)):
            raise PermissionError("Access denied")
        if not p.is_file():
            raise FileNotFoundError("File not found")
        size = p.stat().st_size
        if size > Lse64.MAX_BYTES:
            raise IOError("File too large")
        return p.read_bytes()


def _sample_pdf(title: str) -> bytes:
    content = (
        "%PDF-1.4\n"
        "1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
        "2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n"
        "3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>endobj\n"
        "4 0 obj<< /Length 44 >>stream\n"
        f"BT /F1 12 Tf 72 120 Td ({title.replace(')', '\\)')}) Tj ET\n"
        "endstream endobj\n"
        "xref\n0 5\n0000000000 65535 f \n"
        "trailer<< /Root 1 0 R /Size 5 >>\nstartxref\n0\n%%EOF\n"
    )
    return content.encode("ascii")


if __name__ == "__main__":
    cfg = None  # Provide dict with MySQL details to use a real DB

    # 5 test cases
    p1 = Lse64.upload_pdf(_sample_pdf("Test1"), "report.pdf", cfg)
    print("Uploaded:", p1, "Size:", len(Lse64.download_pdf(p1)))

    p2 = Lse64.upload_pdf(_sample_pdf("Test2"), "../evil.pdf", cfg)
    print("Uploaded:", p2, "Size:", len(Lse64.download_pdf(p2)))

    p3 = Lse64.upload_pdf(_sample_pdf("Test3"), "My Doc.PDF", cfg)
    print("Uploaded:", p3, "Size:", len(Lse64.download_pdf(p3)))

    p4 = Lse64.upload_pdf(_sample_pdf("Test4"), "a_very_long_filename_that_needs_truncation_because_of_fs_limits_and_should_end_with_pdf.pdf", cfg)
    print("Uploaded:", p4, "Size:", len(Lse64.download_pdf(p4)))

    p5 = Lse64.upload_pdf(_sample_pdf("Test5"), "inv@lid name (1).pdf", cfg)
    print("Uploaded:", p5, "Size:", len(Lse64.download_pdf(p5)))