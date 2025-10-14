def transpose(content: str) -> str:
    if content is None:
        return ""
    content = content.replace("\r", "")
    lines = content.split("\n")
    rows = []
    for line in lines:
        if line == "":
            continue
        parts = line.strip().split()  # split by whitespace (robust)
        if parts:
            rows.append(parts)
    if not rows:
        return ""
    r, c = len(rows), len(rows[0])
    out_lines = []
    for i in range(c):
        out_lines.append(" ".join(rows[j][i] for j in range(r)))
    return "\n".join(out_lines)


if __name__ == "__main__":
    tests = [
        "name age\nalice 21\nryan 30",
        "a b c",
        "a\na\na",
        "1 2 3\n4 5 6\n7 8 9",
        "w x y z\n1 2 3 4",
    ]
    for idx, t in enumerate(tests):
        print(transpose(t))
        if idx < len(tests) - 1:
            print("-----")