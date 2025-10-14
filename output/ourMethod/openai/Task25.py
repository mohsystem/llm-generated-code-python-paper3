from typing import List


def number_lines(lines: List[str]) -> List[str]:
    if lines is None or not isinstance(lines, list):
        raise ValueError("Input must be a list of strings.")
    result: List[str] = []
    for idx, item in enumerate(lines, start=1):
        if not isinstance(item, str):
            raise ValueError(f"All items must be strings. Invalid item at index {idx - 1}.")
        result.append(f"{idx}: {item}")
    return result


def _print_test(label: str, data: List[str]) -> None:
    print(f"{label}: {number_lines(data)}")


if __name__ == "__main__":
    # 5 test cases
    _print_test("Test 1", [])
    _print_test("Test 2", ["a", "b", "c"])
    _print_test("Test 3", ["", "x"])
    _print_test("Test 4", ["one line with spaces", "two:with:colons"])
    _print_test("Test 5", ["emoji 😀", "multibyte 字", "punctuation!?", "tabs\tand\nnewlines"])