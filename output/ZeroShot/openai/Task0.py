import os
import hashlib
import threading
import concurrent.futures
import tempfile
import random
import string

# Secure, concurrent processing of files in a directory.
# Returns a dict of absolute file path -> SHA-256 hex digest.
def process_directory(dir_path: str, threads: int) -> dict:
    if dir_path is None:
        raise ValueError("dir_path cannot be None")
    abs_dir = os.path.abspath(os.path.normpath(dir_path))
    if not os.path.isdir(abs_dir) or os.path.islink(abs_dir):
        raise ValueError(f"Not a regular directory: {abs_dir}")

    files = []
    try:
        with os.scandir(abs_dir) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        files.append(os.path.abspath(entry.path))
                except PermissionError:
                    pass
    except FileNotFoundError:
        raise ValueError(f"Directory not found: {abs_dir}")

    max_threads = max(1, min(int(threads or 1), os.cpu_count() * 4 if os.cpu_count() else 8))
    results = {}
    results_lock = threading.Lock()

    def digest_file(path: str):
        # Streaming SHA-256
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            hexval = h.hexdigest()
        except Exception as e:
            hexval = f"ERROR:{type(e).__name__}"
        with results_lock:
            results[path] = hexval

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads, thread_name_prefix="worker") as ex:
        futures = [ex.submit(digest_file, p) for p in files]
        for fut in futures:
            fut.result()  # rethrow exceptions

    return results

# Test helpers
def _populate_files(dir_path: str, count: int, seed: str):
    os.makedirs(dir_path, exist_ok=True)
    rng = random.Random(seed)
    for i in range(count):
        name = f"file_{i:02d}.dat"
        path = os.path.join(dir_path, name)
        # Basic path traversal defense
        ap = os.path.abspath(os.path.normpath(path))
        if not ap.startswith(os.path.abspath(dir_path) + os.sep):
            raise ValueError("Invalid filename")
        with open(ap, "wb") as f:
            size = (i % 17 + 1) * 7
            data = (seed + ":" + "".join(rng.choice(string.ascii_letters) for _ in range(size))).encode("utf-8")
            f.write(data)

if __name__ == "__main__":
    # 5 test cases
    d1 = tempfile.mkdtemp(prefix="cfp1_")
    r1 = process_directory(d1, 4)
    print("Test1 files=", len(r1))

    d2 = tempfile.mkdtemp(prefix="cfp2_")
    _populate_files(d2, 5, "A")
    r2 = process_directory(d2, 2)
    print("Test2 files=", len(r2))

    d3 = tempfile.mkdtemp(prefix="cfp3_")
    _populate_files(d3, 20, "B")
    r3 = process_directory(d3, 4)
    print("Test3 files=", len(r3))

    d4 = tempfile.mkdtemp(prefix="cfp4_")
    _populate_files(d4, 50, "C")
    r4 = process_directory(d4, 8)
    print("Test4 files=", len(r4))

    d5 = tempfile.mkdtemp(prefix="cfp5_")
    _populate_files(d5, 10, "D")
    r5 = process_directory(d5, 1)
    print("Test5 files=", len(r5))