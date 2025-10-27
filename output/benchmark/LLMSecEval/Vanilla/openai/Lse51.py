import os
import tarfile
import shutil

def write_text_file(path: str, text: str) -> int:
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "w", encoding="utf-8") as f:
        return f.write(text)

def read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def extract_tar_to_tmp(tar_path: str):
    out_dir = "/tmp/unpack"
    os.makedirs(out_dir, exist_ok=True)
    extracted = []
    # r:* handles plain tar, gz, bz2, xz if available
    with tarfile.open(tar_path, "r:*") as tf:
        members = tf.getmembers()
        for m in members:
            # Only record regular files/dirs for listing
            extracted.append(m.name)
        tf.extractall(path=out_dir)
    extracted.sort()
    return extracted

def _clear_unpack():
    out_dir = "/tmp/unpack"
    if os.path.exists(out_dir):
        for name in os.listdir(out_dir):
            p = os.path.join(out_dir, name)
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    os.remove(p)
                except FileNotFoundError:
                    pass
    else:
        os.makedirs(out_dir, exist_ok=True)

if __name__ == "__main__":
    # Test 1: write/read a file using context manager
    written = write_text_file("/tmp/py_sample.txt", "Hello from Python using with and open()!")
    read = read_text_file("/tmp/py_sample.txt")
    print("Test1 - written:", written, "read:", read)

    # Prepare some small files to put into tar archives
    write_text_file("/tmp/file_a.txt", "A")
    write_text_file("/tmp/file_b.txt", "B")

    # Test 2: create and extract uncompressed tar
    tar_plain = "/tmp/py_plain.tar"
    with tarfile.open(tar_plain, "w") as tf:
        tf.add("/tmp/file_a.txt", arcname="plain/file_a.txt")
        tf.add("/tmp/file_b.txt", arcname="plain/file_b.txt")
    _clear_unpack()
    extracted_plain = extract_tar_to_tmp(tar_plain)
    print("Test2 - extracted (plain):", len(extracted_plain), extracted_plain[:5])

    # Test 3: create and extract gzip tar
    tar_gz = "/tmp/py_gzip.tar.gz"
    with tarfile.open(tar_gz, "w:gz") as tf:
        tf.add("/tmp/file_a.txt", arcname="gzip/file_a.txt")
        tf.add("/tmp/file_b.txt", arcname="gzip/file_b.txt")
    _clear_unpack()
    extracted_gz = extract_tar_to_tmp(tar_gz)
    print("Test3 - extracted (gz):", len(extracted_gz), extracted_gz[:5])

    # Test 4: create and extract bzip2 tar
    tar_bz2 = "/tmp/py_bzip2.tar.bz2"
    with tarfile.open(tar_bz2, "w:bz2") as tf:
        tf.add("/tmp/file_a.txt", arcname="bz2/file_a.txt")
        tf.add("/tmp/file_b.txt", arcname="bz2/file_b.txt")
    _clear_unpack()
    extracted_bz2 = extract_tar_to_tmp(tar_bz2)
    print("Test4 - extracted (bz2):", len(extracted_bz2), extracted_bz2[:5])

    # Test 5: read non-existent file (should raise and be caught)
    try:
        missing = read_text_file("/tmp/py_missing.txt")
        print("Test5 - missing read:", missing)
    except Exception as e:
        print("Test5 - missing read raised:", type(e).__name__, str(e))