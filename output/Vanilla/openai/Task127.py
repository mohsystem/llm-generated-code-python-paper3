import os
import shutil
import tempfile

def copy_to_temp(source_path: str):
    if source_path is None or not isinstance(source_path, str) or source_path.strip() == "":
        print("[Python] Error: source_path is invalid.", flush=True)
        return None
    try:
        if not os.path.exists(source_path):
            print(f"[Python] Error: Source file does not exist: {source_path}", flush=True)
            return None
        if os.path.isdir(source_path):
            print(f"[Python] Error: Source path is a directory: {source_path}", flush=True)
            return None

        temp_dir = tempfile.gettempdir()
        base = os.path.basename(source_path)
        prefix = f"copy-{base}-"
        fd, dest_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=temp_dir)
        os.close(fd)  # close the file descriptor; we'll copy into it
        shutil.copy2(source_path, dest_path)
        return dest_path
    except Exception as e:
        print(f"[Python] Exception while copying to temp: {e}", flush=True)
        return None

def create_sample_file(content: str):
    try:
        fd, path = tempfile.mkstemp(prefix="task127-sample-", suffix=".txt")
        with os.fdopen(fd, "wb") as f:
            f.write(content.encode("utf-8"))
        return path
    except Exception as e:
        print(f"[Python] Failed to create sample file: {e}", flush=True)
        return None

def files_equal(a: str, b: str):
    try:
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                ba = fa.read(8192)
                bb = fb.read(8192)
                if ba != bb:
                    return False
                if not ba:
                    return True
    except Exception as e:
        print(f"[Python] Failed to compare files: {e}", flush=True)
        return False

if __name__ == "__main__":
    # Test 1: Valid small file
    src1 = create_sample_file("Hello, Task127!")
    dst1 = copy_to_temp(src1)
    print(f"[Python][Test1] src={src1} dst={dst1} equal={bool(dst1 and files_equal(src1, dst1))}")

    # Test 2: Non-existent file
    src2 = os.path.join(tempfile.gettempdir(), "nonexistent_12345_abcdef.txt")
    dst2 = copy_to_temp(src2)
    print(f"[Python][Test2] src={src2} dst={dst2}")

    # Test 3: Directory instead of file
    src3 = tempfile.gettempdir()
    dst3 = copy_to_temp(src3)
    print(f"[Python][Test3] src={src3} dst={dst3}")

    # Test 4: Empty string path
    dst4 = copy_to_temp("")
    print(f"[Python][Test4] src='' dst={dst4}")

    # Test 5: Larger content file
    big = "".join([f"Line {i} - Task127\n" for i in range(10000)])
    src5 = create_sample_file(big)
    dst5 = copy_to_temp(src5)
    print(f"[Python][Test5] src={src5} dst={dst5} equal={bool(dst5 and files_equal(src5, dst5))}")