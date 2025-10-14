import os

def compare_password(file_path, entered_password):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            line = f.readline()
            if line is None:
                stored = ""
            else:
                stored = line.rstrip('\r\n')
    except Exception:
        return False

    if len(stored) != len(entered_password):
        return False

    for a, b in zip(stored, entered_password):
        if a != b:
            return False
    return True

def _write_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == "__main__":
    # Prepare test files
    f1 = "test_pw_1.txt"; _write_file(f1, "hunter2")
    f2 = "test_pw_2.txt"; _write_file(f2, "hunter2")
    f3 = "test_pw_3.txt"; _write_file(f3, "")
    f4 = "test_pw_4.txt"; _write_file(f4, "pass")
    f5 = "test_pw_5.txt"; _write_file(f5, "password")

    # 5 test cases
    print(compare_password(f1, "hunter2"))   # True
    print(compare_password(f2, "hunter3"))   # False
    print(compare_password(f3, ""))          # True
    print(compare_password(f4, "password"))  # False
    print(compare_password(f5, "pass"))      # False