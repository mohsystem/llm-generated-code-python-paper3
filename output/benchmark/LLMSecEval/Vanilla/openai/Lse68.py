import sqlite3
import base64
import os
import random

def upload_image(db_path: str, image_path: str, image_name: str) -> int:
    with open(image_path, 'rb') as f:
        data = f.read()
    b64 = base64.b64encode(data).decode('ascii')

    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                data_base64 TEXT NOT NULL
            )
        """)
        c.execute("INSERT INTO images(name, data_base64) VALUES (?, ?)", (image_name, b64))
        conn.commit()
        return c.lastrowid
    finally:
        conn.close()

def _write_dummy(path: str, size: int, seed: int) -> None:
    rnd = random.Random(seed)
    data = bytes(rnd.getrandbits(8) for _ in range(size))
    with open(path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    db_path = "python_images.db"
    for i in range(1, 6):
        img_path = f"python_img_{i}.bin"
        _write_dummy(img_path, 21 + i, 200 + i)
        rid = upload_image(db_path, img_path, f"python_image_{i}")
        print(f"Python inserted row id: {rid}")