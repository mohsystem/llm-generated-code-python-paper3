import os
import io
import sys
import tarfile
import zipfile
import tempfile
from pathlib import Path
from typing import List

def extract_archive(archive_path: str, dest_dir: str) -> List[str]:
    p = Path(archive_path)
    d = Path(dest_dir)
    d.mkdir(parents=True, exist_ok=True)
    name = p.name.lower()

    def safe_path(base: Path, member: str) -> Path:
        target = (base / member).resolve()
        if not str(target).startswith(str(base.resolve())):
            return None
        return target

    extracted: List[str] = []
    if name.endswith(".zip"):
        with zipfile.ZipFile(p, 'r') as zf:
            for info in zf.infolist():
                member = info.filename
                target = safe_path(d, member)
                if target is None:
                    continue
                if member.endswith('/'):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, 'r') as src, open(target, 'wb') as dst:
                        dst.write(src.read())
                rel = str(target.relative_to(d)).replace("\\", "/")
                extracted.append(rel)
    elif name.endswith(".tar") or name.endswith(".tar.gz") or name.endswith(".tgz"):
        mode = "r:*"
        with tarfile.open(p, mode) as tf:
            for member in tf.getmembers():
                mname = member.name
                target = safe_path(d, mname)
                if target is None:
                    continue
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    f = tf.extractfile(member)
                    if f is not None:
                        with open(target, 'wb') as out:
                            out.write(f.read())
                else:
                    # ignore symlinks/other types
                    continue
                rel = str(target.relative_to(d)).replace("\\", "/")
                extracted.append(rel)
    else:
        raise IOError(f"Unsupported archive type: {archive_path}")
    return extracted

def _create_sample_zip(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dirA/", "")
        zf.writestr("dirA/file1.txt", "Hello from ZIP file1")
        zf.writestr("file2.txt", "Hello from ZIP file2")

def _create_zip_with_zipslip(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../evil.txt", "You should not see me outside")
        zf.writestr("safe.txt", "Safe file")

def _create_sample_tar(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("dirB")
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
        data = b"Hello from TAR file3"
        f = io.BytesIO(data)
        finfo = tarfile.TarInfo("dirB/file3.txt")
        finfo.size = len(data)
        tf.addfile(finfo, f)
        data2 = b"Hello from TAR file4"
        f2 = io.BytesIO(data2)
        finfo2 = tarfile.TarInfo("file4.txt")
        finfo2.size = len(data2)
        tf.addfile(finfo2, f2)

def _create_sample_targz(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo("dirC")
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
        data = b"Hello from TAR.GZ file5"
        f = io.BytesIO(data)
        finfo = tarfile.TarInfo("dirC/file5.txt")
        finfo.size = len(data)
        tf.addfile(finfo, f)
        data2 = b"Hello from TAR.GZ file6"
        f2 = io.BytesIO(data2)
        finfo2 = tarfile.TarInfo("file6.txt")
        finfo2.size = len(data2)
        tf.addfile(finfo2, f2)

if __name__ == "__main__":
    base = Path(tempfile.mkdtemp(prefix="task117_py_"))
    archives = base / "archives"
    outputs = base / "outputs"
    archives.mkdir(parents=True, exist_ok=True)
    outputs.mkdir(parents=True, exist_ok=True)

    zip1 = archives / "sample1.zip"
    tar1 = archives / "sample2.tar"
    tgz1 = archives / "sample3.tar.gz"
    zipslip = archives / "zipslip.zip"
    missing = archives / "missing.zip"

    _create_sample_zip(zip1)
    _create_sample_tar(tar1)
    _create_sample_targz(tgz1)
    _create_zip_with_zipslip(zipslip)

    # Test case 1: ZIP
    out1 = extract_archive(str(zip1), str(outputs / "zip1"))
    print("Test1 ZIP extracted:", out1)

    # Test case 2: TAR
    out2 = extract_archive(str(tar1), str(outputs / "tar1"))
    print("Test2 TAR extracted:", out2)

    # Test case 3: TAR.GZ
    out3 = extract_archive(str(tgz1), str(outputs / "tgz1"))
    print("Test3 TGZ extracted:", out3)

    # Test case 4: ZIP with zip-slip entry (should skip unsafe paths)
    out4 = extract_archive(str(zipslip), str(outputs / "zipslip"))
    print("Test4 ZipSlip extracted (unsafe entries skipped):", out4)

    # Test case 5: Missing
    try:
        out5 = extract_archive(str(missing), str(outputs / "missing"))
        print("Test5 Missing extracted:", out5)
    except Exception as e:
        print("Test5 Missing archive error:", e)

    print("Artifacts in:", str(base.resolve()))