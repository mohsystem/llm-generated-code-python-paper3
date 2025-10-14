import re

def match_lines(file_path):
    pattern = re.compile(r'^\d+.*\.$')
    matches = []
    with open(file_path, 'r', encoding='utf-8', newline='') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if pattern.fullmatch(line):
                matches.append(line)
    return matches

if __name__ == "__main__":
    # Test case 1
    f1 = "py_test1.txt"
    with open(f1, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join([
            "123 Start here.",
            "Not starting with number.",
            "42 Another line.",
            "7 ends with no dot",
            "0."
        ]))
    print("Test 1 matches:", match_lines(f1))

    # Test case 2
    f2 = "py_test2.txt"
    with open(f2, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join([
            "10 Leading digits not ending with dot",
            "20 ends with dot.",
            ". starts with dot.",
            "99Trailing spaces."
        ]))
    print("Test 2 matches:", match_lines(f2))

    # Test case 3
    f3 = "py_test3.txt"
    with open(f3, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join([
            "No numbers at start.",
            "3.14159.",
            "31415",
            "2718."
        ]))
    print("Test 3 matches:", match_lines(f3))

    # Test case 4
    f4 = "py_test4.txt"
    with open(f4, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join([
            "A line.",
            "123.",
            "abc123.",
            "456 trailing spaces .",
            "789!."
        ]))
    print("Test 4 matches:", match_lines(f4))

    # Test case 5 (CRLF endings)
    f5 = "py_test5.txt"
    with open(f5, "wb") as f:
        f.write(b"100 First line.\r\nno number.\r\n200 End with dot.\r\n300 no dot\r\n400.\r\n")
    print("Test 5 matches:", match_lines(f5))