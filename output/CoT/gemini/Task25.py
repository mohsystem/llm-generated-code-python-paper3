def number(lines: list[str]) -> list[str]:
    """
    Prepends line numbers to a list of strings.

    Args:
        lines: The list of strings to number.

    Returns:
        A new list of strings with each line prepended by "n: ".
    """
    return [f"{i}: {line}" for i, line in enumerate(lines, 1)]

# Main block with test cases
if __name__ == "__main__":
    # Test Case 1: Empty list
    test1 = []
    print(f"Test Case 1 (Input: {test1})")
    print(f"Output: {number(test1)}\n")

    # Test Case 2: Standard list
    test2 = ["a", "b", "c"]
    print(f"Test Case 2 (Input: {test2})")
    print(f"Output: {number(test2)}\n")

    # Test Case 3: List with empty strings
    test3 = ["", "", "d"]
    print(f"Test Case 3 (Input: {test3})")
    print(f"Output: {number(test3)}\n")

    # Test Case 4: List with two strings
    test4 = ["Hello", "World"]
    print(f"Test Case 4 (Input: {test4})")
    print(f"Output: {number(test4)}\n")

    # Test Case 5: List with one string
    test5 = ["single line"]
    print(f"Test Case 5 (Input: {test5})")
    print(f"Output: {number(test5)}\n")