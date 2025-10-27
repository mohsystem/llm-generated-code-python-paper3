import os

def write_important_config(path: str) -> int:
    flags = os.O_RDWR | os.O_CREAT
    mode = 0o644  # S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH
    fd = os.open(path, flags, mode)
    try:
        data = b"important_config"
        os.lseek(fd, 0, os.SEEK_SET)
        written = os.write(fd, data)
        return written
    finally:
        os.close(fd)

if __name__ == "__main__":
    print(write_important_config("important_config_py"))
    print(write_important_config("important_config_py_1"))
    print(write_important_config("important_config_py_2"))
    print(write_important_config("important_config_py_3"))
    print(write_important_config("important_config_py_4"))