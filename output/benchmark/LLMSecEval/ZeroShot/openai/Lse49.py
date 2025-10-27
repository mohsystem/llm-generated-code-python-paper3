import os
import io
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import List

def _is_within_directory(base: Path, target: Path) -> bool:
    try:
        base_resolved = base.resolve(strict=False)
        target_resolved = target.resolve(strict=False)
    except Exception:
        return False
    base_str = str(base_resolved)
    target_str = str(target_resolved)
    return target_str == base_str or target_str.startswith(base_str + os.sep)

def _safe_write_file(fp, out_path: Path, max_entry_size: int, total_tracker: dict, max_total_size: int):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(out_path, 'wb') as out_f:
        while True:
            chunk = fp.read(8192)
            if not chunk:
                break
            written += len(chunk)
            total_tracker['total'] += len(chunk)
            if written > max_entry_size:
                raise IOError(f"Entry exceeded size limit: {out_path.name}")
            if total_tracker['total'] > max_total_size:
                raise IOError("Archive exceeded total extraction size limit")
            out_f.write(chunk)
    try:
        os.chmod(out_path, 0o600)
    except Exception:
        pass

def extract_archive(archive_path: str, dest_dir: str) -> List[str]:
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    extracted: List[str] = []

    max_entry_size = 1024 * 1024 * 1024  # 1 GiB per entry
    max_total_size = 2 * 1024 * 1024 * 1024  # 2 GiB total
    total_tracker = {'total': 0}

    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, mode='r:*') as tf:
            for member in tf.getmembers():
                name = member.name or ""
                name = name.replace("\\", "/")
                if name.startswith("/") or name.startswith("\\"):
                    continue
                target = (dest / name).resolve(strict=False)
                if not _is_within_directory(dest, target):
                    continue
                # Skip symlinks and hard links
                if member.issym() or member.islnk():
                    continue
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    try:
                        os.chmod(target, 0o700)
                    except Exception:
                        pass
                    continue
                if member.isreg():
                    if member.size is not None and member.size > max_entry_size:
                        raise IOError(f"Entry too large: {name}")
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with src:
                        _safe_write_file(src, target, max_entry_size, total_tracker, max_total_size)
                    extracted.append(str(target))
    elif zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as zf:
            for zi in zf.infolist():
                name = zi.filename or ""
                name = name.replace("\\", "/")
                if name.startswith("/") or name.startswith("\\"):
                    continue
                target = (dest / name).resolve(strict=False)
                if not _is_within_directory(dest, target):
                    continue
                # Detect symlink in zip via external attributes (POSIX)
                is_symlink = False
                try:
                    mode = (zi.external_attr >> 16) & 0xFFFF
                    is_symlink = stat.S_ISLNK(mode)
                except Exception:
                    is_symlink = False
                if is_symlink:
                    continue
                if name.endswith("/") or (hasattr(zi, "is_dir") and zi.is_dir()):
                    target.mkdir(parents=True, exist_ok=True)
                    try:
                        os.chmod(target, 0o700)
                    except Exception:
                        pass
                    continue
                if zi.file_size is not None and zi.file_size > max_entry_size:
                    raise IOError(f"Entry too large: {name}")
                with zf.open(zi, "r") as fp:
                    _safe_write_file(fp, target, max_entry_size, total_tracker, max_total_size)
                extracted.append(str(target))
    else:
        raise ValueError("Unsupported archive format")

    return extracted

if __name__ == "__main__":
    tests = [
        ("archive.zip", "/tmp/unpack"),
        ("archive.zip", "/tmp/unpack_case2"),
        ("archive.zip", "/tmp/unpack_case3"),
        ("archive.zip", "/tmp/unpack_case4"),
        ("archive.zip", "/tmp/unpack_case5"),
    ]
    for idx, (arc, dest) in enumerate(tests, 1):
        try:
            res = extract_archive(arc, dest)
            print(f"Test {idx}: Extracted {len(res)} entries to {dest}")
        except Exception as e:
            print(f"Test {idx}: Failed to extract to {dest} - {e}")