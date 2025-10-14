from typing import List

def transpose(content: str) -> str:
    if content is None:
        raise ValueError("Input cannot be None")
    trimmed_all = content.replace("\r", "").strip()
    if not trimmed_all:
        return ""

    raw_lines = content.split("\n")
    lines: List[str] = [ln[:-1] if ln.endswith("\r") else ln for ln in raw_lines]

    first_non_empty = -1
    last_non_empty = -1
    for i, ln in enumerate(lines):
        if ln != "":
            first_non_empty = i
            break
    for i in range(len(lines) - 1, -1, -1):
        if lines[i] != "":
            last_non_empty = i
            break
    if first_non_empty == -1:
        return ""

    for i in range(first_non_empty, last_non_empty + 1):
        if lines[i] == "":
            raise ValueError("Empty line detected within data block")

    rows: List[List[str]] = []
    cols = -1
    for i in range(first_non_empty, last_non_empty + 1):
        line = lines[i]
        if line.startswith(" ") or line.endswith(" ") or "  " in line:
            raise ValueError("Invalid spacing: leading/trailing or multiple consecutive spaces")
        tokens = line.split(" ") if line else []
        if cols == -1:
            cols = len(tokens)
        elif len(tokens) != cols:
            raise ValueError("Inconsistent column counts")
        rows.append(tokens)

    if not rows or cols == 0:
        return ""

    out_lines: List[str] = []
    for c in range(cols):
        out_lines.append(" ".join(rows[r][c] for r in range(len(rows))))
    return "\n".join(out_lines)


if __name__ == "__main__":
    tests = [
        "name age\nalice 21\nryan 30",
        "a b c",
        "a\nb\nc",
        "a b\nc d\n",
        "a b\nc"
    ]
    for idx, t in enumerate(tests, 1):
        print(f"Test {idx}:")
        try:
            print(transpose(t))
        except ValueError as e:
            print(f"ERROR: {e}")
        print("----")