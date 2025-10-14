import os
import re
import tempfile

def match_lines_start_num_end_dot(file_path: str):
    matches = []
    if not isinstance(file_path, str) or not file_path:
        return matches
    try:
        if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
            return matches
        pattern = re.compile(r'^\d+.*\.$')
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for raw in f:
                line = raw.rstrip('\n').rstrip('\r')
                if pattern.fullmatch(line):
                    matches.append(line)
    except Exception:
        # In a secure scenario, avoid leaking details, simply return collected results.
        return matches
    return matches

def _write_temp_file(lines):
    fd, path = tempfile.mkstemp(prefix="task99_py_", suffix=".txt")
    os.close(fd)
    with open(path, 'w', encoding='utf-8', errors='strict') as f:
        for s in lines:
            f.write(s + '\n')
    return path

if __name__ == "__main__":
    # Test case 1
    p1 = _write_temp_file([
        "123 This line starts with numbers and ends with a dot.",
        "Not starting with number.",
        "42.",
        "7 ends without dot",
        "007 Bond."
    ])
    print("Test 1:")
    print("\n".join(match_lines_start_num_end_dot(p1)))
    print("----")

    # Test case 2
    p2 = _write_temp_file([
        "1.",
        "22.",
        "333.",
        "4444."
    ])
    print("Test 2:")
    print("\n".join(match_lines_start_num_end_dot(p2)))
    print("----")

    # Test case 3
    p3 = _write_temp_file([
        "hello.",
        ".",
        " no number.",
        "123 but no dot at end",
        ""
    ])
    print("Test 3:")
    print("\n".join(match_lines_start_num_end_dot(p3)))
    print("----")

    # Test case 4
    p4 = _write_temp_file([
        "0.",
        "9 Ends without dot",
        "123abc.",
        "999!.",
        "001 leading zeros."
    ])
    print("Test 4:")
    print("\n".join(match_lines_start_num_end_dot(p4)))
    print("----")

    # Test case 5
    p5 = _write_temp_file([
        "123.456.",
        "10. end.",
        "5... ... ...",
        "8.",
        "12.3"
    ])
    print("Test 5:")
    print("\n".join(match_lines_start_num_end_dot(p5)))
    print("----")