from typing import List

def number_lines(lines: List[str]) -> List[str]:
    """
    Prepends line numbers to each string in a list.

    The numbering starts at 1. The format is "n: string".

    Args:
        lines: A list of strings.

    Returns:
        A new list of strings, with each line numbered.
    """
    # Using enumerate with a starting index of 1 is a concise and Pythonic way to achieve this.
    # The f-string provides safe and readable string formatting.
    return [f"{i}: {line}" for i, line in enumerate(lines, 1)]

if __name__ == '__main__':
    # Test Case 1: Empty list
    test1 = []
    print(f"Test Case 1: Input [] -> Output {number_lines(test1)}")

    # Test Case 2: Basic list
    test2 = ["a", "b", "c"]
    print(f"Test Case 2: Input ['a', 'b', 'c'] -> Output {number_lines(test2)}")

    # Test Case 3: List with empty strings
    test3 = ["first", "", "third"]
    print(f"Test Case 3: Input ['first', '', 'third'] -> Output {number_lines(test3)}")
    
    # Test Case 4: Single element list
    test4 = ["single line"]
    print(f"Test Case 4: Input ['single line'] -> Output {number_lines(test4)}")

    # Test Case 5: List with special characters
    test5 = ["line with numbers 123", "line with symbols !@#"]
    print(f"Test Case 5: Input {test5} -> Output {number_lines(test5)}")