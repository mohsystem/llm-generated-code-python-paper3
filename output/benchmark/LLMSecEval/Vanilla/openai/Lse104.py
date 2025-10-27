import os

def write_important_config(file_path: str) -> int:
    data = b"important_config"
    fd = os.open(file_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        return os.write(fd, data)
    finally:
        os.close(fd)

if __name__ == "__main__":
    tests = [
        "py_test1.txt",
        "py_test2.txt",
        "py_test3.txt",
        "py_test4.txt",
        "py_test5.txt",
    ]
    for t in tests:
        n = write_important_config(t)
        print(f"Wrote {n} bytes to {t}")