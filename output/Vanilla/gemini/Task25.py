def number(lines):
    """
    Takes a list of strings and returns each line prepended by the correct number.
    The numbering starts at 1. The format is n: string.
    :param lines: The list of strings.
    :return: A new list of strings with line numbers.
    """
    return [f"{i}: {line}" for i, line in enumerate(lines, 1)]

if __name__ == '__main__':
    # Test Case 1: Basic case
    input1 = ["a", "b", "c"]
    print("Test Case 1")
    print(f"Input: {input1}")
    print(f"Output: {number(input1)}") # Expected: ['1: a', '2: b', '3: c']
    print()

    # Test Case 2: Empty list
    input2 = []
    print("Test Case 2")
    print(f"Input: {input2}")
    print(f"Output: {number(input2)}") # Expected: []
    print()

    # Test Case 3: List with empty strings
    input3 = ["", "x", ""]
    print("Test Case 3")
    print(f"Input: {input3}")
    print(f"Output: {number(input3)}") # Expected: ['1: ', '2: x', '3: ']
    print()

    # Test Case 4: List with multi-word strings
    input4 = ["hello world", "goodbye world"]
    print("Test Case 4")
    print(f"Input: {input4}")
    print(f"Output: {number(input4)}") # Expected: ['1: hello world', '2: goodbye world']
    print()

    # Test Case 5: Single element list
    input5 = ["Just one line."]
    print("Test Case 5")
    print(f"Input: {input5}")
    print(f"Output: {number(input5)}") # Expected: ['1: Just one line.']
    print()