import os
import sys
import threading
import queue
import tempfile
import uuid

# FNV-1a 64-bit streaming hash
def _fnv1a64_hex(path: str) -> str:
    FNV_OFFSET_BASIS = 0xcbf29ce484222325
    FNV_PRIME = 0x100000001b3
    h = FNV_OFFSET_BASIS
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            for b in chunk:
                h ^= b
                h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"

# Securely list regular files
def _list_regular_files(dir_path: str):
    files = []
    try:
        with os.scandir(dir_path) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        files.append(entry.path)
                except OSError:
                    # Skip entries we can't access
                    pass
    except FileNotFoundError:
        return []
    return files

# Core concurrent processing: returns dict filename -> hash
def process_directory(dir_path: str, thread_count: int):
    if thread_count <= 0:
        raise ValueError("thread_count must be > 0")
    files = _list_regular_files(dir_path)
    q = queue.Queue()
    for p in files:
        q.put(p)
    results = {}
    lock = threading.Lock()

    def worker():
        while True:
            try:
                p = q.get_nowait()
            except queue.Empty:
                break
            try:
                h = _fnv1a64_hex(p)
                name = os.path.basename(p)
                with lock:
                    results[name] = h
            except Exception as e:
                # Log to stderr, continue
                print(f"Error processing {p}: {e}", file=sys.stderr)
            finally:
                q.task_done()

    threads = []
    for _ in range(min(thread_count, max(1, len(files)))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return results

def _write_file(path: str, size_bytes: int, seed: int):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        chunk = bytearray([seed] * 8192)
        remaining = size_bytes
        s = seed
        while remaining > 0:
            to_write = min(len(chunk), remaining)
            f.write(chunk[:to_write])
            remaining -= to_write
            s = (s + 1) & 0xFF
            if to_write == len(chunk):
                chunk[:] = bytes([s]) * len(chunk)

def _create_test_dir(base_name: str) -> str:
    base = tempfile.gettempdir()
    d = os.path.join(base, f"{base_name}-{uuid.uuid4()}")
    os.makedirs(d, exist_ok=True)
    return d

def _print_results(title: str, results: dict):
    print(f"=== {title} ===")
    for k in sorted(results.keys()):
        print(f"{k} -> {results[k]}")
    print()

if __name__ == "__main__":
    # Test 1: 3 small files, 1 thread
    dir1 = _create_test_dir("task0-tc1")
    _write_file(os.path.join(dir1, "a.txt"), 1024, 1)
    _write_file(os.path.join(dir1, "b.txt"), 2048, 2)
    _write_file(os.path.join(dir1, "c.txt"), 4096, 3)
    r1 = process_directory(dir1, 1)
    _print_results("Test 1 (3 files, 1 thread)", r1)

    # Test 2: 10 varied files, 2 threads
    dir2 = _create_test_dir("task0-tc2")
    for i in range(10):
        _write_file(os.path.join(dir2, f"file{i}.bin"), (i + 1) * 1500, 10 + i)
    r2 = process_directory(dir2, 2)
    _print_results("Test 2 (10 files, 2 threads)", r2)

    # Test 3: 5 files incl empty, 4 threads
    dir3 = _create_test_dir("task0-tc3")
    _write_file(os.path.join(dir3, "empty.dat"), 0, 0)
    for i in range(4):
        _write_file(os.path.join(dir3, f"d{i}.dat"), (i + 1) * 8192, 20 + i)
    r3 = process_directory(dir3, 4)
    _print_results("Test 3 (5 files incl empty, 4 threads)", r3)

    # Test 4: empty directory, 3 threads
    dir4 = _create_test_dir("task0-tc4")
    r4 = process_directory(dir4, 3)
    _print_results("Test 4 (0 files, 3 threads)", r4)

    # Test 5: 20 larger files, 8 threads
    import random
    dir5 = _create_test_dir("task0-tc5")
    for i in range(20):
        size = 200 * 1024 + random.randint(0, 50 * 1024)
        _write_file(os.path.join(dir5, f"large_{i:02d}.bin"), size, 30 + i)
    r5 = process_directory(dir5, 8)
    _print_results("Test 5 (20 larger files, 8 threads)", r5)