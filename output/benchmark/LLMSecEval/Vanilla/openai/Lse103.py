import os

def open_file_with_flags(path: str, create: bool, trunc: bool, excl: bool, write_only: bool) -> int:
    flags = 0
    # Access mode
    if trunc or write_only:
        flags |= os.O_WRONLY
    else:
        flags |= os.O_RDONLY
    # Creation and other flags
    if create:
        flags |= os.O_CREAT
    if trunc:
        flags |= os.O_TRUNC
    if excl and create:
        flags |= os.O_EXCL

    mode = 0o644
    try:
        fd = os.open(path, flags, mode)
        os.close(fd)
        return 0
    except OSError as e:
        return -e.errno

def _prepare_file(path: str, create: bool):
    try:
        if not create:
            os.unlink(path)
        else:
            with open(path, "wb") as f:
                f.write(b"seed")
    except FileNotFoundError:
        pass

if __name__ == "__main__":
    # Test 1: Create new file with O_CREAT | O_WRONLY
    f1 = "py_t1_create.txt"
    _prepare_file(f1, False)
    print("T1:", open_file_with_flags(f1, True, False, False, True))

    # Test 2: Truncate existing file with O_TRUNC | O_WRONLY
    f2 = "py_t2_trunc.txt"
    _prepare_file(f2, True)
    print("T2:", open_file_with_flags(f2, False, True, False, True))

    # Test 3: O_CREAT | O_EXCL on existing file should fail
    f3 = "py_t3_excl.txt"
    _prepare_file(f3, True)
    print("T3:", open_file_with_flags(f3, True, False, True, True))

    # Test 4: Open non-existent file without O_CREAT should fail
    f4 = "py_t4_no_create.txt"
    _prepare_file(f4, False)
    print("T4:", open_file_with_flags(f4, False, False, False, True))

    # Test 5: Open existing file O_WRONLY
    f5 = "py_t5_open_existing.txt"
    _prepare_file(f5, True)
    print("T5:", open_file_with_flags(f5, False, False, False, True))