import os
import base64
import mysql.connector
from datetime import datetime
from typing import Tuple

class Lse64:
    DB_HOST = "127.0.0.1"
    DB_PORT = 3306
    DB_NAME = "test"
    DB_USER = "root"
    DB_PASS = ""
    UPLOAD_DIR = "uploads"

    @staticmethod
    def get_connection():
        return mysql.connector.connect(
            host=Lse64.DB_HOST,
            port=Lse64.DB_PORT,
            user=Lse64.DB_USER,
            password=Lse64.DB_PASS,
            database=Lse64.DB_NAME,
            autocommit=True,
        )

    @staticmethod
    def ensure_uploads_dir():
        os.makedirs(Lse64.UPLOAD_DIR, exist_ok=True)

    @staticmethod
    def ensure_table(conn):
        ddl = """
        CREATE TABLE IF NOT EXISTS pdf_uploads (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            filepath VARCHAR(1024) NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        cur = conn.cursor()
        cur.execute(ddl)
        cur.close()

    @staticmethod
    def upload_pdf(file_bytes: bytes, original_filename: str) -> int:
        Lse64.ensure_uploads_dir()
        safe_name = original_filename or "upload.pdf"
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in safe_name)
        if not safe_name.lower().endswith(".pdf"):
            safe_name += ".pdf"
        unique = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        final_name = f"{unique}-{safe_name}"
        file_path = os.path.abspath(os.path.join(Lse64.UPLOAD_DIR, final_name))
        with open(file_path, "wb") as f:
            f.write(file_bytes)
        conn = Lse64.get_connection()
        try:
            Lse64.ensure_table(conn)
            cur = conn.cursor()
            cur.execute("INSERT INTO pdf_uploads (filename, filepath) VALUES (%s, %s)", (original_filename, file_path))
            cur.execute("SELECT LAST_INSERT_ID()")
            row = cur.fetchone()
            cur.close()
            return int(row[0])
        finally:
            conn.close()

    @staticmethod
    def download_pdf(record_id: int) -> bytes:
        conn = Lse64.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT filepath FROM pdf_uploads WHERE id = %s", (record_id,))
            row = cur.fetchone()
            cur.close()
            if not row:
                raise FileNotFoundError(f"No record for id {record_id}")
            path = row[0]
            with open(path, "rb") as f:
                return f.read()
        finally:
            conn.close()

def make_minimal_pdf(message: bytes) -> bytes:
    parts = [
        b"%PDF-1.4\n",
        b"% " + base64.b64encode(message) + b"\n",
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
        b"trailer\n<< /Root 1 0 R >>\n%%EOF\n",
    ]
    return b"".join(parts)

if __name__ == "__main__":
    # 5 test cases
    for i in range(1, 6):
        pdf = make_minimal_pdf(f"Test PDF {i}".encode())
        rid = Lse64.upload_pdf(pdf, f"file{i}.pdf")
        data = Lse64.download_pdf(rid)
        print(f"Inserted id={rid}, downloaded bytes={len(data)}")