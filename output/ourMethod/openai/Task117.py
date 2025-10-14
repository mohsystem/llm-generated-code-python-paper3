import os
import sys
import io
import stat
import tarfile
import zipfile
import tempfile
from pathlib import Path
from typing import List, Tuple


def extract_archive(archive_path: str, dest_dir: str, max_total_size: int = 100 * 1024 * 1024) -> List[str]:
    if not isinstance(archive_path, str) or not isinstance(dest_dir, str):
        raise ValueError("archive_path and dest_dir must be strings")
    if max_total_size <= 0:
        raise ValueError("max_total_size must be positive")

    ap = archive_path.lower()
    if ap.endswith(".zip"):
        return [str(p) for p in extract_zip(Path(archive_path), Path(dest_dir), max_total_size)]
    elif ap.endswith(".tar") or ap.endswith(".tar.gz") or ap.endswith(".tgz"):
        return [str(p) for p in extract_tar(Path(archive_path), Path(dest_dir), max_total_size)]
    else:
        raise ValueError(f"Unsupported archive type: {archive_path}")


def extract_zip(archive_path: Path, dest_dir: Path, max_total_size: int) -> List[Path]:
    _validate_path_types(archive_path, dest_dir)
    _create_base_dir(dest_dir)
    extracted: List[Path] = []
    total = 0

    with zipfile.ZipFile(archive_path, 'r') as zf:
        for info in zf.infolist():
            name = info.filename
            _validate_entry_name(name)
            target = _resolve_safe_path(dest_dir, name)

            # Detect symlink via Unix attributes if present and reject
            is_symlink = False
            if info.external_attr != 0:
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    is_symlink = True
            if is_symlink:
                raise IOError(f"Refusing to extract symlink entry: {name}")

            if name.endswith('/') or info.is_dir():
                _secure_mkdirs(target, dest_dir)
                continue

            _secure_mkdirs(target.parent, dest_dir)

            declared = info.file_size
            if declared is not None and declared > 0:
                if declared > max_total_size - total:
                    raise IOError("Archive exceeds maximum allowed total size")

            with zf.open(info, 'r') as fsrc:
                written = _write_file_safely(fsrc, target)
                total = _safe_add(total, written, max_total_size)
                extracted.append(target)
    return extracted


def extract_tar(archive_path: Path, dest_dir: Path, max_total_size: int) -> List[Path]:
    _validate_path_types(archive_path, dest_dir)
    _create_base_dir(dest_dir)
    extracted: List[Path] = []
    total = 0

    mode = 'r:*'  # auto-detect compression
    with tarfile.open(archive_path, mode) as tf:
        for member in tf.getmembers():
            name = member.name
            _validate_entry_name(name)
            target = _resolve_safe_path(dest_dir, name)

            if member.issym() or member.islnk():
                raise IOError(f"Refusing to extract link entry: {name}")

            if member.isdir():
                _secure_mkdirs(target, dest_dir)
                continue

            if member.isreg():
                if member.size > max_total_size - total:
                    raise IOError("Archive exceeds maximum allowed total size")
                _secure_mkdirs(target.parent, dest_dir)
                src = tf.extractfile(member)
                if src is None:
                    raise IOError(f"Failed to read member: {name}")
                with src:
                    written = _write_file_safely(src, target)
                total = _safe_add(total, written, max_total_size)
                extracted.append(target)
            else:
                # Skip other types
                continue
    return extracted


def _validate_path_types(archive_path: Path, dest_dir: Path) -> None:
    if not isinstance(archive_path, Path) or not isinstance(dest_dir, Path):
        raise ValueError("archive_path and dest_dir must be Path objects")
    if not archive_path.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")


def _validate_entry_name(name: str) -> None:
    if not isinstance(name, str):
        raise IOError("Entry name must be a string")
    if len(name) == 0:
        raise IOError("Empty entry name")
    if len(name) > 4096:
        raise IOError("Entry name too long")


def _create_base_dir(base: Path) -> None:
    if base.exists():
        if base.is_symlink():
            raise IOError("Destination base is a symlink")
        if not base.is_dir():
            raise IOError("Destination exists and is not a directory")
    else:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)


def _resolve_safe_path(base: Path, entry_name: str) -> Path:
    norm = entry_name.replace('\\', '/')
    while norm.startswith("./"):
        norm = norm[2:]
    rel = Path(norm)
    if rel.is_absolute():
        raise IOError(f"Absolute path not allowed: {entry_name}")
    if any(part == ".." for part in rel.parts):
        raise IOError(f"Path traversal detected: {entry_name}")
    target = (base / rel).resolve()
    base_resolved = base.resolve()
    try:
        target.relative_to(base_resolved)
    except ValueError:
        raise IOError(f"Resolved path escapes base directory: {entry_name}")
    return target


def _secure_mkdirs(dir_path: Path, base: Path) -> None:
    if dir_path is None:
        return
    base_resolved = base.resolve()
    current = base_resolved
    rel_parts = dir_path.resolve().relative_to(base_resolved).parts if dir_path.exists() else dir_path.relative_to(base).parts
    walker = base
    for part in rel_parts:
        walker = walker / part
        if walker.exists():
            if walker.is_symlink():
                raise IOError(f"Refusing to use symlinked directory: {walker}")
            if not walker.is_dir():
                raise IOError(f"Path component is not a directory: {walker}")
        else:
            os.mkdir(walker, 0o700)


def _write_file_safely(src_stream: io.BufferedReader, target: Path) -> int:
    parent = target.parent
    if not parent.exists():
        raise IOError("Parent directory must exist before writing file")
    # Check for symlink ancestors
    p = parent
    while True:
        if p.is_symlink():
            raise IOError(f"Refusing to use symlink ancestor: {p}")
        if p == p.parent:
            break
        p = p.parent

    # Write to temp file in the same directory
    fd, tmp_path_str = tempfile.mkstemp(prefix=".extract-", suffix=".part", dir=str(parent))
    tmp_path = Path(tmp_path_str)
    total_written = 0
    try:
        with os.fdopen(fd, "wb", buffering=0) as tmpf:
            while True:
                chunk = src_stream.read(8192)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                tmpf.write(chunk)
                total_written += len(chunk)
            tmpf.flush()
            os.fsync(tmpf.fileno())
        os.chmod(tmp_path, 0o600)
        # Atomic move; fail if target exists to avoid races
        if target.exists():
            raise FileExistsError(f"Target already exists: {target}")
        os.replace(tmp_path, target)
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass
        raise
    return total_written


def _safe_add(a: int, b: int, limit: int) -> int:
    r = a + b
    if r < a or r > limit:
        raise IOError("Size limit exceeded")
    return r


def _create_sample_zip(base: Path) -> Path:
    zip_path = base / "sample.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "Hello A\n")
        zf.writestr("dir/b.txt", "Hello B\n")
        zf.writestr("../evil.txt", "nope\n")  # should be rejected
        zf.writestr("/abs.txt", "nope abs\n")  # should be rejected
    return zip_path


def _create_sample_tar(base: Path) -> Path:
    tar_path = base / "sample.tar"
    with tarfile.open(tar_path, "w") as tf:
        ti = tarfile.TarInfo("x.txt")
        data = b"Hi X\n"
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

        tf.addfile(tarfile.TarInfo("dir/"))  # directory
        ti2 = tarfile.TarInfo("dir/y.txt")
        data2 = b"Hi Y\n"
        ti2.size = len(data2)
        tf.addfile(ti2, io.BytesIO(data2))

        # traversal
        ti3 = tarfile.TarInfo("../pwn.txt")
        d3 = b"No\n"
        ti3.size = len(d3)
        tf.addfile(ti3, io.BytesIO(d3))

        # symlink
        ti4 = tarfile.TarInfo("alink")
        ti4.type = tarfile.SYMTYPE
        ti4.linkname = "target"
        tf.addfile(ti4)
    return tar_path


def main() -> None:
    temp_root = Path(tempfile.mkdtemp(prefix="extractor-tests-"))
    print(f"Temp root: {temp_root}")

    # Test 1: Simple ZIP extraction
    try:
        zip_path = _create_sample_zip(temp_root)
        out1 = temp_root / "out1"
        files1 = extract_archive(str(zip_path), str(out1), 10 * 1024 * 1024)
        print("Test1 ZIP extracted files:")
        for p in files1:
            print(" -", str(Path(p).relative_to(temp_root)))
    except Exception as e:
        print("Test1 failed:", e)

    # Test 2: ZIP explicit call with traversal entries
    try:
        zip_path = _create_sample_zip(temp_root)
        out2 = temp_root / "out2"
        files2 = extract_zip(zip_path, out2, 10 * 1024 * 1024)
        print("Test2 ZIP explicit extracted files:")
        for p in files2:
            print(" -", str(p.relative_to(temp_root)))
    except Exception as e:
        print("Test2 failed (expected some rejections):", e)

    # Test 3: TAR extraction with symlink and traversal (should raise)
    try:
        tar_path = _create_sample_tar(temp_root)
        out3 = temp_root / "out3"
        files3 = extract_archive(str(tar_path), str(out3), 10 * 1024 * 1024)
        print("Test3 TAR extracted files:")
        for p in files3:
            print(" -", str(Path(p).relative_to(temp_root)))
    except Exception as e:
        print("Test3 failed (expected refusal):", e)

    # Test 4: TGZ extraction
    try:
        tar_path = _create_sample_tar(temp_root)
        tgz_path = temp_root / "sample.tgz"
        import gzip
        with open(tar_path, "rb") as fin, gzip.open(tgz_path, "wb") as fout:
            while True:
                chunk = fin.read(8192)
                if not chunk:
                    break
                fout.write(chunk)
        out4 = temp_root / "out4"
        files4 = extract_archive(str(tgz_path), str(out4), 10 * 1024 * 1024)
        print("Test4 TGZ extracted files:")
        for p in files4:
            print(" -", str(Path(p).relative_to(temp_root)))
    except Exception as e:
        print("Test4 failed:", e)

    # Test 5: Size limit enforcement
    try:
        big_zip = temp_root / "big.zip"
        with zipfile.ZipFile(big_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", b"\x00" * (1024 * 1024))  # 1MB
        out5 = temp_root / "out5"
        files5 = extract_archive(str(big_zip), str(out5), 512 * 1024)  # 512KB limit
        print("Test5 extracted files (unexpected):", files5)
    except Exception as e:
        print("Test5 size limit enforcement worked:", e)


if __name__ == "__main__":
    main()