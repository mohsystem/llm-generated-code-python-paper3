import sqlite3
import base64
import re

MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB
NAME_PATTERN = re.compile(r'^[A-Za-z0-9._-]{1,255}$')

def init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

def is_valid_image_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    return NAME_PATTERN.match(name) is not None

def upload_image(conn: sqlite3.Connection, image_name: str, image_bytes: bytes) -> int:
    if conn is None:
        raise ValueError("conn cannot be None")
    if not is_valid_image_name(image_name):
        return -1
    if not isinstance(image_bytes, (bytes, bytearray)) or len(image_bytes) == 0 or len(image_bytes) > MAX_IMAGE_SIZE:
        return -1

    b64 = base64.b64encode(image_bytes).decode('ascii')
    with conn:
        cur = conn.execute("INSERT INTO images(name, data) VALUES(?, ?)", (image_name, b64))
        return cur.lastrowid if cur.lastrowid is not None else -1

def _repeat(byte_val: int, count: int) -> bytes:
    return bytes([byte_val & 0xFF]) * count

def main():
    conn = sqlite3.connect(":memory:")
    init_db(conn)

    img1 = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])  # PNG header
    img2 = bytes([0xFF, 0xD8, 0xFF, 0xE0])  # JPEG header
    img3 = b'GIF89a'  # GIF header
    img4 = _repeat(0xAB, 1024)  # 1KB data
    img5 = _repeat(0xCD, 2048)  # 2KB data

    id1 = upload_image(conn, "sample1.png", img1)
    id2 = upload_image(conn, "photo-02.jpg", img2)
    id3 = upload_image(conn, "icon.gif", img3)
    id4 = upload_image(conn, "large_block.bin", img4)
    id5 = upload_image(conn, "data_chunk.dat", img5)

    print("Inserted IDs:", id1, id2, id3, id4, id5)
    row = conn.execute("SELECT COUNT(*) FROM images").fetchone()
    print("Total rows:", row[0] if row else 0)

if __name__ == "__main__":
    main()