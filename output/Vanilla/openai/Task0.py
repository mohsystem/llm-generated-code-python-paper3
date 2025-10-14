import os
import threading
import queue
import tempfile
import random

def process_directory(dir_path: str, thread_count: int):
    if not os.path.isdir(dir_path):
        raise ValueError(f"Not a directory: {dir_path}")
    q = queue.Queue()
    for entry in os.scandir(dir_path):
        if entry.is_file():
            q.put(entry.path)

    results = {}
    results_lock = threading.Lock()

    def worker():
        while True:
            try:
                path = q.get_nowait()
            except queue.Empty:
                break
            s = 0
            try:
                with open(path, 'rb') as f:
                    while True:
                        b = f.read(8192)
                        if not b:
                            break
                        s += sum(b)
            except Exception:
                s = -1
            with results_lock:
                results[os.path.basename(path)] = s
            q.task_done()

    threads = []
    for _ in range(max(1, thread_count)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return results

def _create_test_dir(prefix: str, files: int, min_kb: int = 32, max_kb: int = 128):
    d = tempfile.mkdtemp(prefix=prefix)
    for i in range(files):
        size_kb = random.randint(min_kb, max_kb)
        path = os.path.join(d, f"file_{i}.dat")
        with open(path, 'wb') as f:
            remaining = size_kb * 1024
            while remaining > 0:
                chunk = min(remaining, 8192)
                f.write(os.urandom(chunk))
                remaining -= chunk
    return d

def _run_test_case(name: str, files: int, threads: int):
    d = _create_test_dir(name + "_", files)
    print(f"Test {name} - dir: {d} threads: {threads}")
    res = process_directory(d, threads)
    for k in sorted(res.keys()):
        print(f"  {k} -> checksum={res[k]}")
    print()

if __name__ == "__main__":
    _run_test_case("case1", 5, 1)
    _run_test_case("case2", 6, 2)
    _run_test_case("case3", 7, 3)
    _run_test_case("case4", 8, 4)
    _run_test_case("case5", 9, 5)