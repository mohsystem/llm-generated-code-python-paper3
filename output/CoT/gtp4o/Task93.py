from collections import OrderedDict
import os

# Step 1-5 summarized in concise implementation with safe parsing and file handling.

def read_and_sort_key_values(file_path: str) -> OrderedDict:
    if file_path is None:
        raise ValueError("file_path cannot be None")
    max_file_size = 10 * 1024 * 1024  # 10 MB
    max_key_len = 4096
    max_value_len = 2_000_000

    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)
    if os.path.isdir(file_path):
        raise IsADirectoryError(file_path)
    try:
        size = os.path.getsize(file_path)
        if size > max_file_size:
            raise IOError("File too large")
    except OSError:
        pass

    sorted_map = dict()
    total_value_bytes = 0
    with open(file_path, "r", encoding="utf-8", newline="") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            idx_eq = line.find("=")
            idx_col = line.find(":")
            if idx_eq == -1 and idx_col == -1:
                continue
            if idx_eq == -1:
                idx = idx_col
            elif idx_col == -1:
                idx = idx_eq
            else:
                idx = min(idx_eq, idx_col)

            key = line[:idx].strip()
            value = line[idx + 1 :].strip()
            if not key:
                continue
            if len(key) > max_key_len:
                raise IOError("Key too long")
            if len(value) > max_value_len:
                raise IOError("Value too long")
            total_value_bytes += len(value)
            if total_value_bytes > max_file_size:
                raise IOError("Accumulated values exceed safe threshold")

            sorted_map[key] = value  # last occurrence wins

    ordered = OrderedDict()
    for k in sorted(sorted_map.keys()):
        ordered[k] = sorted_map[k]
    return ordered


def _write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def _run_test(title: str, filename: str, content: str) -> None:
    _write_file(filename, content)
    result = read_and_sort_key_values(filename)
    print(f"=== {title} ({filename}) ===")
    for k, v in result.items():
        print(f"{k}={v}")


if __name__ == "__main__":
    # 5 test cases
    _run_test("Test 1 - Basic", "py_test_kv_1.txt",
              "banana=yellow\napple=red\ncarrot=orange\n")
    _run_test("Test 2 - Unsorted with spaces", "py_test_kv_2.txt",
              "  zeta = 26 \nalpha=1\nbeta = 2\n  gamma= 3\n")
    _run_test("Test 3 - Duplicates", "py_test_kv_3.txt",
              "a=1\na=2\nb=3\nA=upper\n")
    _run_test("Test 4 - Mixed separators and comments", "py_test_kv_4.txt",
              "# Comment line\n// Another comment\nhost: localhost\nport=8080\n user : admin \npassword = secret\n")
    _run_test("Test 5 - Special characters", "py_test_kv_5.txt",
              "path=/usr/local/bin\nkey.with.dots=value.with.dots\n spaced key = spaced value \nemoji=🙂\ncolon:used\n")