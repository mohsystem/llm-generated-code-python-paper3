import os
import tempfile

def _constant_time_equals(a: str, b: str) -> bool:
    if a is None:
        a = ""
    if b is None:
        b = ""
    la = len(a)
    lb = len(b)
    maxlen = max(la, lb)
    diff = la ^ lb
    for i in range(maxlen):
        ac = ord(a[i]) if i < la else 0
        bc = ord(b[i]) if i < lb else 0
        diff |= (ac ^ bc)
    return diff == 0

def compare_password_from_file(file_path: str, user_input: str) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            line = f.readline()
            if line is None:
                line = ""
            else:
                # strip only trailing newline
                line = line.rstrip("\n")
        return _constant_time_equals(line, user_input)
    except OSError:
        return False

if __name__ == "__main__":
    # Test files
    tmp_files = []

    # Test case 1: exact match
    f1 = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
    f1.write("Secret123!")
    f1.flush(); f1.close()
    tmp_files.append(f1.name)
    print(compare_password_from_file(f1.name, "Secret123!"))

    # Test case 2: mismatch
    f2 = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
    f2.write("Secret123!")
    f2.flush(); f2.close()
    tmp_files.append(f2.name)
    print(compare_password_from_file(f2.name, "secret123!"))

    # Test case 3: different length
    f3 = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
    f3.write("Short")
    f3.flush(); f3.close()
    tmp_files.append(f3.name)
    print(compare_password_from_file(f3.name, "Shorter"))

    # Test case 4: trailing newline in file
    f4 = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
    f4.write("WithNewline\n")
    f4.flush(); f4.close()
    tmp_files.append(f4.name)
    print(compare_password_from_file(f4.name, "WithNewline"))

    # Test case 5: file not found
    print(compare_password_from_file("nonexistent_file_abcdefg.txt", "anything"))

    for p in tmp_files:
        try:
            os.unlink(p)
        except Exception:
            pass