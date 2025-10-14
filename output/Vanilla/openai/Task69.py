import os
import sys
import tempfile
import time

def delete_file(path: str) -> bool:
    if not path:
        return False
    try:
        os.remove(path)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            res = delete_file(arg)
            print(f"{arg} -> {res}")
        sys.exit(0)

    # 5 test cases
    paths = []
    # 1-3: create temp files to delete
    f1 = tempfile.NamedTemporaryFile(delete=False, prefix="Task69_test_1_", suffix=".tmp")
    f1.write(b"data1")
    f1.close()
    f2 = tempfile.NamedTemporaryFile(delete=False, prefix="Task69_test_2_", suffix=".tmp")
    f2.write(b"data2")
    f2.close()
    f3 = tempfile.NamedTemporaryFile(delete=False, prefix="Task69_test_3_", suffix=".tmp")
    f3.write(b"data3")
    f3.close()

    paths.append(f1.name)  # 1: existing file
    paths.append(f2.name)  # 2: existing file
    paths.append(f3.name)  # 3: existing file

    # 4: non-existent file
    non_existent = os.path.join(tempfile.gettempdir(), f"Task69_nonexistent_{time.time_ns()}.tmp")
    paths.append(non_existent)

    # 5: try to delete the first file again (already deleted)
    paths.append(f1.name)

    for p in paths:
        result = delete_file(p)
        print(f"{p} -> {result}")