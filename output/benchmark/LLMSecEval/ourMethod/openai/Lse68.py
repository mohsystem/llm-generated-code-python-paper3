import base64
import os
import re
import sqlite3
import stat
import tempfile

MAX_IMAGE_SIZE = 1 * 1024 * 1024  # 1 MiB
NAME_MAX = 255

SAFE_NAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,' + str(NAME_MAX) + r'}$')

class Database:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE images (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data TEXT NOT NULL)")
        cur.close()

    def insert_image(self, name: str, data_b64: str) -> int:
        if not SAFE_NAME_RE.match(name):
            raise ValueError("Bad name")
        if not data_b64 or len(data_b64) > MAX_IMAGE_SIZE * 2:
            raise ValueError("Bad data")
        cur = self.conn.cursor()
        cur.execute("INSERT INTO images(name, data) VALUES(?, ?)", (name, data_b64))
        last_id = cur.lastrowid
        cur.close()
        return last_id

    def count(self) -> int:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM images")
        c = cur.fetchone()[0]
        cur.close()
        return c

    def all(self):
        cur = self.conn.cursor()
        cur.execute("SELECT id, name, LENGTH(data) FROM images ORDER BY id")
        rows = cur.fetchall()
        cur.close()
        return rows

def _is_safe_simple_name(s: str) -> bool:
    return isinstance(s, str) and SAFE_NAME_RE.match(s) is not None

def upload_image(base_dir: str, relative_file_name: str, image_name: str, db: Database) -> bool:
    if not (_is_safe_simple_name(relative_file_name) and _is_safe_simple_name(image_name)):
        print("Rejected: invalid name")
        return False

    dir_fd = None
    file_fd = None
    try:
        dir_fd = os.open(base_dir, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        # Open relative to base dir, do not follow symlinks
        kwargs = {"dir_fd": dir_fd}
        if "follow_symlinks" in os.open.__code__.co_varnames:
            kwargs["follow_symlinks"] = False
        file_fd = os.open(relative_file_name, flags, **kwargs)

        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            print("Rejected: not a regular file")
            return False
        if st.st_size > MAX_IMAGE_SIZE:
            print("Rejected: file too large")
            return False

        total = 0
        chunks = []
        while True:
            chunk = os.read(file_fd, 8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_IMAGE_SIZE:
                print("Rejected: file too large (during read)")
                return False
            chunks.append(chunk)
        data = b"".join(chunks)
        data_b64 = base64.b64encode(data).decode("ascii")
        db.insert_image(image_name, data_b64)
        return True
    except Exception as e:
        print("Failed:", str(e))
        return False
    finally:
        if file_fd is not None:
            try: os.close(file_fd)
            except Exception: pass
        if dir_fd is not None:
            try: os.close(dir_fd)
            except Exception: pass

def _write_file(base_dir: str, name: str, size: int):
    path = os.path.join(base_dir, name)
    with open(path, "wb") as f:
        remaining = size
        chunk = os.urandom(4096)
        while remaining > 0:
            w = min(len(chunk), remaining)
            f.write(chunk[:w])
            remaining -= w

def main():
    db = Database()
    with tempfile.TemporaryDirectory(prefix="img_upload_py_") as base_dir:
        print("Base directory:", base_dir)

        _is = 1024
        _write_file(base_dir, "t1.bin", _is)
        _write_file(base_dir, "t2.bin", 2048)
        _write_file(base_dir, "t3.bin", 512)
        _write_file(base_dir, "big.bin", 2 * 1024 * 1024)  # 2 MiB oversize

        r1 = upload_image(base_dir, "t1.bin", "image_one.png", db)
        print("Test1 (valid):", r1)

        r2 = upload_image(base_dir, "t2.bin", "image-two.jpg", db)
        print("Test2 (valid):", r2)

        r3 = upload_image(base_dir, "big.bin", "too_big.dat", db)
        print("Test3 (oversize):", r3)

        r4 = upload_image(base_dir, "t_missing.bin", "missing.gif", db)
        print("Test4 (missing):", r4)

        r5 = upload_image(base_dir, "t3.bin", "safe_name-ok_123.bmp", db)
        print("Test5 (valid):", r5)

        print("DB count:", db.count())
        for row in db.all():
            print("Record id=", row[0], "name=", row[1], "b64_len=", row[2])

if __name__ == "__main__":
    main()