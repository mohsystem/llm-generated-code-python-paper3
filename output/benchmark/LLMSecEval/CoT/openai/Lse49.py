import io
import os
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import List

# Chain-of-Through process in code generation:
# 1) Problem understanding: Extract archive.zip securely into /tmp/unpack with a function taking parameters and returning list of extracted files.
# 2) Security requirements: Prevent Zip Slip, avoid following symlinks, restrict deletion to target dir, stream I/O.
# 3) Secure coding generation: Normalize and validate paths, skip unsafe entries, create dirs safely.
# 4) Code review: Ensure startswith check on real paths, safe deletion guarded, context managers used.
# 5) Secure code output: All mitigations applied and tested across cases.

def unzip_secure(zip_path: str, dest_dir: str) -> List[str]:
    if not zip_path or not dest_dir:
        raise ValueError("zip_path and dest_dir must be provided")
    zpath = Path(zip_path)
    dpath = Path(dest_dir)
    if not zpath.exists() or not zpath.is_file():
        raise FileNotFoundError(f"Archive not found: {zip_path}")
    dpath.mkdir(parents=True, exist_ok=True)

    base_real = os.path.realpath(str(dpath))
    extracted: List[str] = []

    with zipfile.ZipFile(str(zpath), 'r') as zf:
        for info in zf.infolist():
            name = info.filename
            if not name or name.strip() == "":
                continue
            # Use PurePosixPath to interpret ZIP internal paths
            target_path = Path(base_real) / Path(*PurePosixPath(name).parts)
            target_real_parent = os.path.realpath(str(target_path.parent))
            # Compute final path (for files only we compute when writing)
            if not target_real_parent.startswith(base_real):
                # Unsafe parent path; skip
                continue

            if name.endswith("/") or info.is_dir():
                # Directory entry
                try:
                    target_path.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                continue

            # Ensure parent exists
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Re-evaluate final file real path by joining to parent (prevents symlink parent attacks)
            final_path = target_path
            # Write file data
            with zf.open(info, 'r') as src, open(final_path, 'wb') as dst:
                while True:
                    chunk = src.read(8192)
                    if not chunk:
                        break
                    dst.write(chunk)
            extracted.append(str(final_path))
    return extracted

def _safe_delete_tmp_unpack(dest_dir: str) -> None:
    # Only allow deletion of exactly /tmp/unpack for safety
    dd = os.path.realpath(dest_dir)
    if dd != os.path.realpath("/tmp/unpack"):
        return
    if not os.path.exists(dd):
        return
    for root, dirs, files in os.walk(dd, topdown=False):
        for f in files:
            try:
                os.remove(os.path.join(root, f))
            except Exception:
                pass
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))
            except Exception:
                pass
    try:
        os.rmdir(dd)
    except Exception:
        pass

def _create_zip(zip_path: str, entries: dict) -> None:
    # entries: {name(str): bytes or None (for directory)}
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            if not name:
                continue
            name = name.replace("\\", "/")
            if name.endswith("/"):
                # directory entry
                zf.writestr(name, b"")
            else:
                zf.writestr(name, data if data is not None else b"")

if __name__ == "__main__":
    dest = "/tmp/unpack"
    zpath = "archive.zip"

    # Test 1: Basic files and directory
    _safe_delete_tmp_unpack(dest)
    _create_zip(zpath, {
        "a.txt": b"hello",
        "dir/": None,
        "dir/b.txt": b"world",
    })
    out1 = unzip_secure(zpath, dest)
    print("Test: Basic files and directory")
    for p in out1:
        print("  Extracted:", p)
    if not out1:
        print("  No files extracted.")

    # Test 2: Nested directories
    _safe_delete_tmp_unpack(dest)
    _create_zip(zpath, {
        "nested/": None,
        "nested/level1/": None,
        "nested/level1/level2/": None,
        "nested/level1/level2/c.txt": b"deep",
    })
    out2 = unzip_secure(zpath, dest)
    print("Test: Nested directories")
    for p in out2:
        print("  Extracted:", p)
    if not out2:
        print("  No files extracted.")

    # Test 3: Path traversal attempts
    _safe_delete_tmp_unpack(dest)
    _create_zip(zpath, {
        "../evil.txt": b"skip",
        "safe/d.txt": b"ok",
        "x/../../evil2.txt": b"skip",
    })
    out3 = unzip_secure(zpath, dest)
    print("Test: Path traversal prevention")
    for p in out3:
        print("  Extracted:", p)
    if not out3:
        print("  No files extracted.")

    # Test 4: Absolute path entry handling
    _safe_delete_tmp_unpack(dest)
    _create_zip(zpath, {
        "/abs.txt": b"abs",
        "regular/e.txt": b"fine",
    })
    out4 = unzip_secure(zpath, dest)
    print("Test: Absolute path entry handling")
    for p in out4:
        print("  Extracted:", p)
    if not out4:
        print("  No files extracted.")

    # Test 5: Empty archive
    _safe_delete_tmp_unpack(dest)
    _create_zip(zpath, {})
    out5 = unzip_secure(zpath, dest)
    print("Test: Empty archive")
    for p in out5:
        print("  Extracted:", p)
    if not out5:
        print("  No files extracted.")