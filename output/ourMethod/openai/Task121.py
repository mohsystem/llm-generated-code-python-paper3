import os
import re
from typing import Dict, Any

MAX_SIZE = 1_048_576  # 1 MiB
NAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,100}$')


def upload_file(base_dir: str, original_name: str, data: bytes) -> Dict[str, Any]:
    if not isinstance(base_dir, str) or not base_dir:
        return {"success": False, "message": "Base directory is required.", "saved_path": None}
    if not isinstance(original_name, str) or not original_name:
        return {"success": False, "message": "Filename is required.", "saved_path": None}
    if NAME_RE.fullmatch(original_name) is None:
        return {"success": False, "message": "Invalid filename. Allowed: A-Z, a-z, 0-9, ., _, - with length 1..100.", "saved_path": None}
    if not isinstance(data, (bytes, bytearray)):
        return {"success": False, "message": "Data must be bytes.", "saved_path": None}
    if len(data) == 0:
        return {"success": False, "message": "File is empty.", "saved_path": None}
    if len(data) > MAX_SIZE:
        return {"success": False, "message": f"File too large. Max {MAX_SIZE} bytes.", "saved_path": None}

    try:
        os.makedirs(base_dir, exist_ok=True)
        base_real = os.path.realpath(base_dir)

        # Split name and extension
        base_name, ext = os.path.splitext(original_name)

        for counter in range(10000):
            candidate_name = f"{base_name}{ext}" if counter == 0 else f"{base_name}({counter}){ext}"
            final_path = os.path.join(base_real, candidate_name)
            # Ensure normalized path remains within base
            final_real_parent = os.path.realpath(os.path.dirname(final_path))
            if final_real_parent != base_real:
                continue

            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            try:
                # Avoid following symlinks where available
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW  # type: ignore[attr-defined]
                fd = os.open(final_path, flags, 0o600)
            except FileExistsError:
                continue
            except FileNotFoundError:
                # Parent missing unexpectedly (shouldn't happen)
                return {"success": False, "message": "Parent directory missing.", "saved_path": None}
            except PermissionError as pe:
                return {"success": False, "message": f"Permission error: {pe}", "saved_path": None}
            except OSError as oe:
                # If failure due to symlink or other issue, try next or fail
                # ELOOP or others may indicate symlink encountered
                if getattr(oe, "errno", None) == getattr(__import__("errno"), "EEXIST", 17):
                    continue
                # For other errors, return
                return {"success": False, "message": f"I/O error: {oe}", "saved_path": None}

            try:
                with os.fdopen(fd, "wb", closefd=True) as f:
                    # Write in chunks to avoid large memory spikes
                    view = memoryview(data)
                    written = 0
                    chunk_size = 64 * 1024
                    for i in range(0, len(view), chunk_size):
                        n = f.write(view[i:i + chunk_size])
                        if n is None:
                            return {"success": False, "message": "Write failed.", "saved_path": None}
                        written += n
                    f.flush()
                    os.fsync(f.fileno())
                # Confirm it's a regular file (not a symlink)
                st = os.lstat(final_path)
                if not (st.st_mode & 0o170000 == 0o100000):  # S_IFREG
                    try:
                        os.remove(final_path)
                    except Exception:
                        pass
                    return {"success": False, "message": "Upload failed: not a regular file.", "saved_path": None}
                return {"success": True, "message": "Upload successful.", "saved_path": final_path}
            except Exception as e:
                # Attempt cleanup if partial file exists
                try:
                    os.remove(final_path)
                except Exception:
                    pass
                return {"success": False, "message": f"I/O error: {e}", "saved_path": None}

        return {"success": False, "message": "Could not allocate a unique filename.", "saved_path": None}
    except Exception as e:
        return {"success": False, "message": f"Unexpected error: {e}", "saved_path": None}


def _print_result(label: str, res: Dict[str, Any]) -> None:
    print(f"{label}: success={res.get('success')} message={res.get('message')} saved_path={res.get('saved_path')}")


if __name__ == "__main__":
    base_dir = "uploads_python"
    data1 = b"Hello, world!"
    data2 = b"Another file content"
    data3 = b"A" * (MAX_SIZE + 1)
    data4 = b"Small"
    data5 = b"Duplicate name test"

    r1 = upload_file(base_dir, "hello.txt", data1)
    _print_result("Test 1", r1)

    r2 = upload_file(base_dir, "bad/evil.txt", data2)
    _print_result("Test 2", r2)

    r3 = upload_file(base_dir, "big.bin", data3)
    _print_result("Test 3", r3)

    r4 = upload_file(base_dir, "../secret.txt", data4)
    _print_result("Test 4", r4)

    r5a = upload_file(base_dir, "hello.txt", data5)
    _print_result("Test 5a", r5a)
    r5b = upload_file(base_dir, "hello.txt", data5)
    _print_result("Test 5b", r5b)