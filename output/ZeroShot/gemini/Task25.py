def number(lines: list[str]) -> list[str]:
    """
    Prepends line numbers to a list of strings.
    The numbering starts at 1. The format is n: string.
    
    :param lines: A list of strings.
    :return: A new list of strings with line numbers.
    """
    return [f"{i}: {line}" for i, line in enumerate(lines, 1)]

if __name__ == '__main__':
    # Test cases
    test_cases = [
        ([], []), # Test Case 1: Empty list
        (["a", "b", "c"], ["1: a", "2: b", "3: c"]), # Test Case 2: Simple list
        (["", "hello", ""], ["1: ", "2: hello", "3: "]), # Test Case 3: List with empty strings
        (["First line", "Second line"], ["1: First line", "2: Second line"]), # Test Case 4: Longer strings
        (["single"], ["1: single"]) # Test Case 5: Single element list
    ]

    for i, (input_list, expected) in enumerate(test_cases, 1):
        result = number(input_list)
        print(f"Test Case {i} Input: {input_list}")
        print(f"Output: {result}")
        assert result == expected
        print()