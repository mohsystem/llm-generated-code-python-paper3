# Chain-of-Through process in code generation:
# 1) Problem understanding: Provide upload_image that reads an image file, converts to base64, and inserts name+base64 into a database.
# 2) Security requirements: Validate image name, cap file size, safe file handling, thread-safe DB.
# 3) Secure coding generation: Implement robust input checks, error handling, and safe use of base64.
# 4) Code review: Ensure limits, name validation, and locking are in place.
# 5) Secure code output: Finalized code with mitigations.

import base64
import os
import threading
import tempfile
from typing import List, Tuple, Optional

class SafeDatabase:
    def __init__(self) -> None:
        self._store: List[Tuple[str, str]] = []
        self._lock = threading.Lock()

    def insert(self, name: str, b64: str) -> bool:
        if name is None or b64 is None:
            return False
        with self._lock:
            self._store.append((name, b64))
            return True

    def get_all(self) -> List[Tuple[str, str]]:
        with self._lock:
            return list(self._store)

    def count(self) -> int:
        with self._lock:
            return len(self._store)

def _is_valid_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if len(name) < 1 or len(name) > 100:
        return False
    for ch in name:
        if not (ch.isalnum() or ch in "._-"):
            return False
    return True

def _read_file_capped(path: str, max_bytes: int) -> Optional[bytes]:
    try:
        if not os.path.isfile(path):
            return None
        size = os.path.getsize(path)
        if size < 0 or size > max_bytes:
            return None
        with open(path, "rb") as f:
            data = f.read()
            if len(data) != size or len(data) > max_bytes:
                return None
            return data
    except Exception:
        return None

# upload_image: reads an image from file_path, converts to base64, inserts into db with image_name. Returns True on success.
def upload_image(db: SafeDatabase, image_name: str, file_path: str) -> bool:
    if db is None or not _is_valid_name(image_name):
        return False
    MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
    data = _read_file_capped(os.path.abspath(file_path), MAX_BYTES)
    if data is None:
        return False
    b64 = base64.b64encode(data).decode('ascii')
    return db.insert(image_name, b64)

if __name__ == "__main__":
    db = SafeDatabase()
    temp_dir = tempfile.mkdtemp(prefix="lse68_py_imgs_")
    paths = []
    # Create 5 test binary files
    for i in range(5):
        sz = 128 + i * 64
        content = bytes(((i * 37 + j) & 0xFF) for j in range(sz))
        p = os.path.join(temp_dir, f"test_{i+1}.bin")
        with open(p, "wb") as f:
            f.write(content)
        paths.append(p)

    names = ["img1.png", "photo-02.jpg", "scan_03.tif", "icon-4.bmp", "graph5.svg"]

    # 5 test cases
    for i in range(5):
        ok = upload_image(db, names[i], paths[i])
        print(f"Test {i+1} inserted={ok}")

    print(f"Total records: {db.count()}")
    for name, b64 in db.get_all():
        preview = b64[:20]
        print(f"Name={name}, b64_preview={preview}...")