import os
import re
import tempfile

_pattern = re.compile(r'^\d+.*\.$')

def match_lines_start_num_end_dot(file_path: str):
    if file_path is None:
        raise ValueError("file_path must not be None")
    matches = []
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            s = line.rstrip('\r\n')
            if _pattern.match(s):
                matches.append(s)
    return matches

def _create_temp_file_with_lines(lines):
    fd, path = tempfile.mkstemp(prefix="task99_", suffix=".txt")
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            for s in lines:
                f.write(s)
                f.write('\n')
    except Exception:
        try:
            os.remove(path)
        finally:
            raise
    return path

def _print_test(title, out):
    print(title)
    for s in out:
        print(s)
    print('---')

if __name__ == '__main__':
    # Test 1
    f1 = _create_temp_file_with_lines([
        "123.",
        "1abc.",
        "abc.",
        "123",
        " 123.",
        "456.."
    ])
    _print_test("Test 1", match_lines_start_num_end_dot(f1))
    os.remove(f1)

    # Test 2: empty file
    f2 = _create_temp_file_with_lines([])
    _print_test("Test 2", match_lines_start_num_end_dot(f2))
    os.remove(f2)

    # Test 3: whitespace and numbers
    f3 = _create_temp_file_with_lines([
        "\t789.",
        "000.",
        "000. ",
        "999.x",
        "42."
    ])
    _print_test("Test 3", match_lines_start_num_end_dot(f3))
    os.remove(f3)

    # Test 4: mixed punctuation
    f4 = _create_temp_file_with_lines([
        "7!@#$.",
        "5text.",
        "0042..",
        "nope.",
        "9"
    ])
    _print_test("Test 4", match_lines_start_num_end_dot(f4))
    os.remove(f4)

    # Test 5: long lines and edge cases
    long_line = 'x' * 1000
    f5 = _create_temp_file_with_lines([
        "1" + long_line + ".",
        long_line + ".",
        "2.",
        "3. ",
        "4.."
    ])
    _print_test("Test 5", match_lines_start_num_end_dot(f5))
    os.remove(f5)