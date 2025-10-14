import os
import sys
import threading
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor
import tempfile

def _is_within(base_real: str, path_real: str) -> bool:
    base_real = os.path.join(base_real, '')
    return path_real.startswith(base_real)

def _list_regular_files(base_dir: str) -> List[str]:
    files: List[str] = []
    with os.scandir(base_dir) as it:
        for entry in it:
            try:
                if entry.is_symlink():
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                real = os.path.realpath(entry.path)
                if not _is_within(os.path.realpath(base_dir), real):
                    continue
                files.append(real)
            except Exception:
                continue
    return files

# Cross-platform best-effort file lock: use fcntl on POSIX; on Windows use in-process mutex map
_has_fcntl = False
try:
    import fcntl  # type: ignore
    _has_fcntl = True
except Exception:
    _has_fcntl = False

_inproc_locks: Dict[str, threading.Lock] = {}
_inproc_locks_guard = threading.Lock()

def _acquire_lock(path: str):
    if _has_fcntl:
        fd = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except Exception:
            os.close(fd)
            raise
        return ("fcntl", fd)
    else:
        with _inproc_locks_guard:
            lock = _inproc_locks.get(path)
            if lock is None:
                lock = threading.Lock()
                _inproc_locks[path] = lock
        lock.acquire()
        return ("inproc", lock)

def _release_lock(lockinfo):
    kind, obj = lockinfo
    if kind == "fcntl":
        try:
            fcntl.flock(obj, fcntl.LOCK_UN)  # type: ignore
        finally:
            os.close(obj)
    elif kind == "inproc":
        obj.release()

def _fnv1a64_update(h: int, data: bytes) -> int:
    prime = 0x100000001B3
    for b in data:
        h ^= b
        h = (h * prime) & 0xFFFFFFFFFFFFFFFF
    return h

def process_directory(base_dir: str, workers: int) -> Dict[str, str]:
    if not isinstance(base_dir, str):
        raise TypeError("base_dir must be a string")
    if not isinstance(workers, int) or workers <= 0 or workers > 128:
        raise ValueError("workers must be in 1..128")

    base_dir = os.path.abspath(base_dir)
    if os.path.islink(base_dir):
        raise OSError("Base directory must not be a symlink")
    if not os.path.isdir(base_dir):
        raise OSError("Base path is not a directory")
    base_real = os.path.realpath(base_dir)

    files = _list_regular_files(base_real)
    q_lock = threading.Lock()
    idx = {"i": 0}
    results: Dict[str, str] = {}
    results_lock = threading.Lock()

    def worker():
        while True:
            with q_lock:
                if idx["i"] >= len(files):
                    return
                path = files[idx["i"]]
                idx["i"] += 1
            try:
                # Validate still within base and not a symlink
                if os.path.islink(path):
                    continue
                real = os.path.realpath(path)
                if not _is_within(base_real, real):
                    continue

                lockinfo = _acquire_lock(real)
                try:
                    # Process: compute FNV-1a(64) hash
                    h = 0xCBF29CE484222325
                    with open(real, "rb", buffering=0) as f:
                        while True:
                            chunk = f.read(8192)
                            if not chunk:
                                break
                            h = _fnv1a64_update(h, chunk)
                    hexval = f"{h & 0xFFFFFFFFFFFFFFFF:016x}"
                    name = os.path.basename(real)
                    with results_lock:
                        results[name] = hexval
                finally:
                    _release_lock(lockinfo)
            except Exception:
                name = os.path.basename(path)
                with results_lock:
                    results[name] = "ERROR"

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(worker) for _ in range(workers)]
        for f in futures:
            f.result()

    # Return sorted dict
    return {k: results[k] for k in sorted(results.keys())}

def _write_file(dirpath: str, name: str, content: str) -> None:
    p = os.path.abspath(os.path.join(dirpath, name))
    base = os.path.abspath(dirpath)
    if not _is_within(base, p):
        raise OSError("Invalid file name")
    with open(p, "wb") as f:
        data = content.encode("utf-8")
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass

def main():
    tmp = tempfile.mkdtemp(prefix="concurrent_proc_py_")
    try:
        _write_file(tmp, "file1.txt", "Alpha\n" * 10000)
        _write_file(tmp, "file2.txt", "Bravo\n" * 8000)
        _write_file(tmp, "file3.txt", "Charlie\n" * 12000)
        _write_file(tmp, "file4.txt", "Delta\n" * 5000)
        _write_file(tmp, "file5.txt", "Echo\n" * 15000)

        res = process_directory(tmp, 4)
        print("Processed files and FNV-1a(64) hashes:")
        for k in sorted(res.keys()):
            print(f"{k} -> {res[k]}")
    finally:
        try:
            for name in os.listdir(tmp):
                try:
                    os.remove(os.path.join(tmp, name))
                except Exception:
                    pass
            os.rmdir(tmp)
        except Exception:
            pass

if __name__ == "__main__":
    main()