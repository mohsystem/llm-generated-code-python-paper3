import os
import sys

MAX_SIZE = 10 * 1024 * 1024  # 10MB

def read_file_secure(path: str):
    if not path:
        return None
    try:
        base = os.path.realpath(os.getcwd())
        canon = os.path.realpath(path)

        # Ensure target is within base directory
        if not (canon == base or canon.startswith(base + os.sep)):
            return None

        if not os.path.isfile(canon):
            return None

        size = os.path.getsize(canon)
        if size > MAX_SIZE:
            return None

        with open(canon, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return None

def main():
    if len(sys.argv) > 1:
        for p in sys.argv[1:]:
            print(f"----- {p} -----")
            content = read_file_secure(p)
            if content is not None:
                print(content)
            else:
                print("ERROR: Unable to read file securely.")
        return

    # 5 test cases
    try:
        with open("py_t1.txt", "w", encoding="utf-8") as f:
            f.write("Python Test 1: Hello World")

        os.makedirs("py_subdir", exist_ok=True)
        with open(os.path.join("py_subdir", "py_t2.txt"), "w", encoding="utf-8") as f:
            f.write("Python Test 2: Inside subdir")

        tests = [
            "py_t1.txt",                       # valid
            os.path.join("py_subdir", "py_t2.txt"),  # valid in subdir
            "py_no_such.txt",                  # non-existent
            "py_subdir",                       # directory
            os.path.join("..", "py_outside.txt")  # escape attempt
        ]

        for p in tests:
            print(f"===== Testing: {p} =====")
            content = read_file_secure(p)
            if content is not None:
                print(content)
            else:
                print("ERROR: Unable to read file securely.")
    except Exception as e:
        print(f"ERROR: Test setup failed: {e}")

if __name__ == "__main__":
    main()