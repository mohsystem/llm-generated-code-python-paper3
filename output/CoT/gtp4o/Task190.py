from typing import List

def transpose(lines: List[str]) -> str:
    if lines is None:
        raise ValueError("Input lines cannot be None")
    if len(lines) == 0:
        return ""
    matrix: List[List[str]] = []
    cols = -1
    for line in lines:
        if line is None:
            raise ValueError("A line is None")
        tokens = line.strip().split()
        if not tokens:
            raise ValueError("Empty line not allowed")
        if cols == -1:
            cols = len(tokens)
        elif cols != len(tokens):
            raise ValueError("Inconsistent column count")
        matrix.append(tokens)
    rows = len(matrix)
    out_lines: List[str] = []
    for c in range(cols):
        out_lines.append(" ".join(matrix[r][c] for r in range(rows)))
    return "\n".join(out_lines)

if __name__ == "__main__":
    # 5 test cases

    # 1) Example from prompt
    tc1 = [
        "name age",
        "alice 21",
        "ryan 30"
    ]
    print("TC1:\n" + transpose(tc1) + "\n")

    # 2) 1x1
    tc2 = ["a"]
    print("TC2:\n" + transpose(tc2) + "\n")

    # 3) 1x3
    tc3 = ["x y z"]
    print("TC3:\n" + transpose(tc3) + "\n")

    # 4) 3x1
    tc4 = ["x", "y", "z"]
    print("TC4:\n" + transpose(tc4) + "\n")

    # 5) 3x3
    tc5 = [
        "a b c",
        "d e f",
        "g h i"
    ]
    print("TC5:\n" + transpose(tc5) + "\n")