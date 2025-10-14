import os
import sys
import uuid
import tempfile
from pathlib import Path

def delete_file_secure(path: str) -> bool:
    if not isinstance(path, str) or not path.strip():
        return False
    try:
        p = Path(path).absolute()
        # Avoid deleting root or drive root
        if p.parent == p:
            return False
        if not p.exists():
            return False
        if p.is_dir():
            return False  # refuse directories
        p.unlink()
        return True
    except Exception:
        return False

def _run_tests():
    try:
        f1 = tempfile.NamedTemporaryFile(delete=False); f1.close()
        f2 = tempfile.NamedTemporaryFile(delete=False); f2.close()
        f3 = tempfile.NamedTemporaryFile(delete=False); f3.close()
        d = tempfile.mkdtemp(prefix="task69_dir_")
        nonexist = os.path.join(d, "nonexistent_" + uuid.uuid4().hex + ".tmp")

        print("Test1 delete file:", delete_file_secure(f1.name))
        print("Test2 delete file:", delete_file_secure(f2.name))
        print("Test3 delete directory (should be False):", delete_file_secure(d))
        print("Test4 delete non-existent (should be False):", delete_file_secure(nonexist))
        print("Test5 delete file:", delete_file_secure(f3.name))

        try:
            os.rmdir(d)
        except Exception:
            pass
    except Exception as e:
        print("Setup failed:", str(e))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            print(f"{a} -> {delete_file_secure(a)}")
    else:
        _run_tests()