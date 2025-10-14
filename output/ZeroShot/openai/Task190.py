from typing import List

def transpose_text(lines: List[str]) -> List[str]:
    if lines is None:
        raise ValueError("lines cannot be None")
    if not lines:
        return []
    matrix: List[List[str]] = []
    cols = -1
    for i, line in enumerate(lines):
        if line is None:
            raise ValueError(f"line {i} is None")
        tokens = line.strip().split()
        if i == 0:
            cols = len(tokens)
            if cols == 0:
                raise ValueError("first line has no tokens")
        else:
            if len(tokens) != cols:
                raise ValueError(f"inconsistent columns at row {i}")
        matrix.append(tokens)
    result: List[str] = []
    for c in range(cols):
        result.append(" ".join(row[c] for row in matrix))
    return result

def _run_test(idx: int, lines: List[str]) -> None:
    out = transpose_text(lines)
    print(f"Test {idx} output:")
    for line in out:
        print(line)
    print("---")

if __name__ == "__main__":
    # Test 1: Sample
    _run_test(1, [
        "name age",
        "alice 21",
        "ryan 30",
    ])
    # Test 2: Single row
    _run_test(2, [
        "a b c",
    ])
    # Test 3: Single column
    _run_test(3, [
        "a",
        "b",
        "c",
    ])
    # Test 4: Multiple spaces and trims
    _run_test(4, [
        "x   y",
        " 1    2 ",
    ])
    # Test 5: 2x2
    _run_test(5, [
        "p q",
        "r s",
    ])