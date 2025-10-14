from __future__ import annotations
import os
import io
import tempfile
import stat
from typing import List, Tuple


def _trim(s: str) -> str:
    return s.strip()


def read_and_sort_key_value_file(base_dir: str, relative_path: str) -> List[Tuple[str, str]]:
    if not isinstance(base_dir, str) or not isinstance(relative_path, str):
        raise TypeError("base_dir and relative_path must be strings")
    if not base_dir:
        raise ValueError("base_dir must not be empty")
    if not relative_path or len(relative_path) > 4096 or "\x00" in relative_path:
        raise ValueError("Invalid relative_path")
    if os.path.isabs(relative_path):
        raise PermissionError("Absolute paths are not allowed")

    base_real = os.path.realpath(base_dir)
    if not os.path.isdir(base_real):
        raise FileNotFoundError("Base directory not found")

    candidate = os.path.normpath(os.path.join(base_real, relative_path))
    try:
        common = os.path.commonpath([base_real, candidate])
    except ValueError:
        raise PermissionError("Resolved path escapes base directory")
    if common != base_real:
        raise PermissionError("Resolved path escapes base directory")

    try:
        st = os.lstat(candidate)
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError("Refusing to process symlink")
    if not stat.S_ISREG(st.st_mode):
        raise PermissionError("Not a regular file")

    records: List[Tuple[str, str]] = []
    with io.open(candidate, "r", encoding="utf-8", newline="") as f:
        for line in f:
            if len(line) > 8192:
                continue
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("#") or trimmed.startswith(";"):
                continue
            if "=" not in trimmed:
                continue
            k, v = trimmed.split("=", 1)
            k = _trim(k)
            v = _trim(v)
            if not k or not v or len(k) > 1024 or len(v) > 4096:
                continue
            records.append((k, v))

    records.sort(key=lambda kv: (kv[0], kv[1]))
    return records


def _secure_write_file(base_dir: str, name: str, lines: List[str]) -> str:
    if not name or len(name) > 255 or "\x00" in name:
        raise ValueError("Invalid file name")
    base_real = os.path.realpath(base_dir)
    target_norm = os.path.normpath(os.path.join(base_real, name))
    try:
        common = os.path.commonpath([base_real, target_norm])
    except ValueError:
        raise PermissionError("Write path escapes base directory")
    if common != base_real:
        raise PermissionError("Write path escapes base directory")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = 0o600
    fd = os.open(target_norm, flags, mode)
    try:
        data = "".join(line + ("\n" if not line.endswith("\n") else "") for line in lines)
        b = data.encode("utf-8")
        total = 0
        while total < len(b):
            written = os.write(fd, b[total:])
            if written <= 0:
                raise IOError("Failed to write file")
            total += written
        os.fsync(fd)
    finally:
        os.close(fd)
    return target_norm


def _print_result(title: str, records: List[Tuple[str, str]]) -> None:
    print(title)
    for k, v in records:
        print(f"  {k}={v}")


def main() -> None:
    base = tempfile.mkdtemp(prefix="task93_kv_")

    # Test 1: Normal case
    _secure_write_file(base, "test1.txt", ["b=2", "a=1", "c=3"])
    r1 = read_and_sort_key_value_file(base, "test1.txt")
    _print_result("Test1 sorted:", r1)

    # Test 2: Whitespace, comments, malformed lines
    _secure_write_file(base, "test2.txt", ["   # comment", " b = x ", "a= y", "invalidline", "=novalue", "keyonly="])
    r2 = read_and_sort_key_value_file(base, "test2.txt")
    _print_result("Test2 sorted:", r2)

    # Test 3: Duplicate keys
    _secure_write_file(base, "test3.txt", ["dup=2", "dup=1", "alpha=zz", "alpha=aa"])
    r3 = read_and_sort_key_value_file(base, "test3.txt")
    _print_result("Test3 sorted:", r3)

    # Test 4: Path traversal attempt
    try:
        read_and_sort_key_value_file(base, "../outside.txt")
        print("Test4: Unexpected success")
    except Exception as ex:
        print(f"Test4 caught expected error: {ex}")

    # Test 5: Absolute path attempt
    abs_path = os.path.join(base, "test5.txt")
    _secure_write_file(base, "test5.txt", ["z=last", "m=mid", "a=first"])
    try:
        read_and_sort_key_value_file(base, abs_path)
        print("Test5: Unexpected success")
    except Exception as ex:
        print(f"Test5 caught expected error: {ex}")


if __name__ == "__main__":
    main()