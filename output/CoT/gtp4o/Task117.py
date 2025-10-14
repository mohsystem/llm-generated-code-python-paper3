import io
import os
import tarfile
import zipfile
import gzip
from pathlib import Path
import tempfile

# Secure helpers

def _resolve_secure(base_dir: Path, entry_name: str) -> Path:
    # Prevent absolute paths and normalize
    if entry_name.startswith("/") or entry_name.startswith("\\"):
        raise ValueError("Absolute paths are not allowed")
    target = (base_dir / entry_name).resolve()
    base = base_dir.resolve()
    if not str(target).startswith(str(base) + os.sep) and target != base:
        raise ValueError("Path traversal attempt blocked: " + entry_name)
    return target

def _copy_with_limit(src_fh, dst_fh, max_remaining: int) -> int:
    total = 0
    buf = bytearray(8192)
    while True:
        chunk = src_fh.readinto(buf)
        if not chunk:
            break
        if total + chunk > max_remaining:
            allowed = max(0, max_remaining - total)
            if allowed > 0:
                dst_fh.write(buf[:allowed])
                total += allowed
            raise IOError("Extraction aborted: size limit exceeded")
        dst_fh.write(buf[:chunk])
        total += chunk
    return total

# ZIP extraction

def extract_zip_secure(zip_path: str, dest_dir: str, max_total_bytes: int) -> int:
    base = Path(dest_dir)
    base.mkdir(parents=True, exist_ok=True)
    count = 0
    total = 0
    with zipfile.ZipFile(zip_path, 'r') as z:
        for info in z.infolist():
            name = info.filename
            if "\x00" in name:
                continue
            try:
                target = _resolve_secure(base, name)
            except ValueError:
                continue
            if name.endswith('/'):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info, 'r') as src, open(target, 'wb') as dst:
                written = _copy_with_limit(src, dst, max_total_bytes - total)
                total += written
                count += 1
    return count

# TAR extraction
def extract_tar_secure(tar_path: str, dest_dir: str, max_total_bytes: int) -> int:
    return _extract_tar_generic(tar_path, dest_dir, max_total_bytes, gz=False)

def extract_targz_secure(targz_path: str, dest_dir: str, max_total_bytes: int) -> int:
    return _extract_tar_generic(targz_path, dest_dir, max_total_bytes, gz=True)

def _extract_tar_generic(path: str, dest_dir: str, max_total_bytes: int, gz: bool) -> int:
    base = Path(dest_dir)
    base.mkdir(parents=True, exist_ok=True)
    count = 0
    total = 0

    # Open tar with or without gzip
    if gz:
        fh = gzip.open(path, 'rb')
        tf = tarfile.open(fileobj=fh, mode='r:*')
    else:
        tf = tarfile.open(path, 'r:*')

    try:
        for member in tf.getmembers():
            name = member.name
            # block absolute and NUL
            if "\x00" in name or name.startswith("/") or name.startswith("\\"):
                continue
            # skip symlinks and hardlinks for safety
            if member.issym() or member.islnk():
                continue
            try:
                target = _resolve_secure(base, name)
            except ValueError:
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    continue
                with src, open(target, 'wb') as dst:
                    written = _copy_with_limit(src, dst, max_total_bytes - total)
                    total += written
                    count += 1
    finally:
        tf.close()
        if gz:
            fh.close()
    return count

# Helpers to create archives for tests
def create_sample_zip(path: Path):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('dir/', '')
        z.writestr('dir/a.txt', 'Hello from a.txt')
        z.writestr('b.txt', 'Hello from b.txt')

def create_traversal_zip(path: Path):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('safe.txt', 'safe')
        z.writestr('../evil.txt', 'evil')

def create_sample_tar(path: Path):
    with tarfile.open(path, 'w') as tf:
        data1 = b'Hello from tar a.txt'
        ti1 = tarfile.TarInfo('dir/')
        ti1.type = tarfile.DIRTYPE
        tf.addfile(ti1)
        t2 = tarfile.TarInfo('dir/a.txt')
        t2.size = len(data1)
        tf.addfile(t2, io.BytesIO(data1))
        data2 = b'Hello from tar b.txt'
        t3 = tarfile.TarInfo('b.txt')
        t3.size = len(data2)
        tf.addfile(t3, io.BytesIO(data2))

def create_sample_targz(path: Path):
    tmp = path.with_suffix('.tmp.tar')
    try:
        create_sample_tar(tmp)
        with open(tmp, 'rb') as src, gzip.open(path, 'wb') as gz:
            gz.write(src.read())
    finally:
        if tmp.exists():
            tmp.unlink()

def create_large_zip(path: Path, size_bytes: int):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('large.bin', b'\x01' * size_bytes)

def main():
    base = Path(tempfile.mkdtemp(prefix='task117_py_'))
    print(f"Python tests working dir: {base}")

    # Test 1: simple zip
    zip1 = base / 'sample.zip'
    out1 = base / 'out_zip1'
    create_sample_zip(zip1)
    c1 = extract_zip_secure(str(zip1), str(out1), 10_000_000)
    print("Test1 ZIP extracted files:", c1)

    # Test 2: traversal zip
    zip2 = base / 'trav.zip'
    out2 = base / 'out_zip2'
    create_traversal_zip(zip2)
    c2 = extract_zip_secure(str(zip2), str(out2), 10_000_000)
    print("Test2 ZIP extracted files (expect 1):", c2)

    # Test 3: sample tar
    tar1 = base / 'sample.tar'
    out3 = base / 'out_tar1'
    create_sample_tar(tar1)
    c3 = extract_tar_secure(str(tar1), str(out3), 10_000_000)
    print("Test3 TAR extracted files:", c3)

    # Test 4: sample tar.gz
    tgz1 = base / 'sample.tgz'
    out4 = base / 'out_tgz1'
    create_sample_targz(tgz1)
    c4 = extract_targz_secure(str(tgz1), str(out4), 10_000_000)
    print("Test4 TAR.GZ extracted files:", c4)

    # Test 5: size limit
    zip_large = base / 'large.zip'
    out5 = base / 'out_zip_large'
    create_large_zip(zip_large, 2_000_000)
    try:
        extract_zip_secure(str(zip_large), str(out5), 100_000)
        print("Test5 ZIP size limit: FAILED")
    except Exception as e:
        print("Test5 ZIP size limit: PASSED", str(e))

if __name__ == "__main__":
    main()