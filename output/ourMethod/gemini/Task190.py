import os
from typing import List, Tuple

def transpose_file(file_path: str) -> str:
    """
    Transposes the content of a text file.
    
    Args:
        file_path: The path to the text file.
    
    Returns:
        A string with the transposed content, or an error message.
    """
    if not os.path.exists(file_path):
        return "Error: File not found."
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        if not lines:
            return ""

        grid = [line.strip().split() for line in lines if line.strip()]
        
        if not grid:
            return ""

        transposed_grid = list(zip(*grid))
        return "\n".join([" ".join(row) for row in transposed_grid])

    except IOError as e:
        return f"Error reading file: {e}"

def create_test_file(file_name: str, content: str):
    """Helper function to create a file with given content."""
    with open(file_name, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    """Main function with test cases."""
    test_cases: List[Tuple[str, str]] = [
        ("name age\nalice 21\nryan 30", "name alice ryan\nage 21 30"),
        ("a b c\nd e f", "a d\nb e\nc f"),
        ("single_word", "single_word"),
        ("1 2 3 4 5", "1\n2\n3\n4\n5"),
        ("", "")
    ]

    test_file_name = "file.txt"

    for i, (content, expected) in enumerate(test_cases):
        print(f"--- Test Case {i + 1} ---")
        try:
            create_test_file(test_file_name, content)
            result = transpose_file(test_file_name)
            
            print("Input:")
            print(content if content else "<empty file>")
            print("\nOutput:")
            print(result)
            print("\nExpected:")
            print(expected)
            print(f"Test Passed: {result == expected}")

        except Exception as e:
            print(f"Test case {i + 1} failed with an exception: {e}")
        finally:
            if os.path.exists(test_file_name):
                os.remove(test_file_name)
        print("--------------------")

    print("--- Test Case 6 (File not found) ---")
    result = transpose_file("non_existent_file.txt")
    expected_error = "Error: File not found."
    print("Output:")
    print(result)
    print("\nExpected:")
    print(expected_error)
    print(f"Test Passed: {result == expected_error}")
    print("--------------------")


if __name__ == "__main__":
    main()