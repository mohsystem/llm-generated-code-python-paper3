import os

def transpose_file_content(filename: str) -> str:
    """
    Reads a space-delimited text file, transposes its content, and returns the result.
    Assumes all rows have the same number of columns.
    """
    try:
        # Secure: 'with' statement ensures the file is closed properly, even if errors occur.
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if not lines:
            return ""

        # Remove trailing newlines and split into words.
        # This handles lines that might be empty or just whitespace correctly.
        grid = [line.rstrip('\n').split(' ') for line in lines]
        
        if not grid:
            return ""

        # The zip(*...) idiom is a concise and efficient way to transpose a matrix (list of lists).
        # It handles empty input gracefully.
        transposed_grid = list(zip(*grid))

        # Join the elements of each new row with spaces, then join the rows with newlines.
        return "\n".join([" ".join(row) for row in transposed_grid])

    except FileNotFoundError:
        # Secure: Handle the case where the file doesn't exist to prevent crashes.
        print(f"Error: File not found at '{filename}'")
        return ""
    except Exception as e:
        # Secure: Catch other potential exceptions during file processing for robustness.
        print(f"An error occurred: {e}")
        return ""

def run_test_case(test_num: int, content: str, expected: str):
    """Helper function to run a single test case."""
    filename = "file.txt"
    print(f"--- Test Case {test_num} ---")
    try:
        # Create the test file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)

        result = transpose_file_content(filename)
        print(f"Input:\n{content if content else '(empty)'}")
        print(f"\nOutput:\n{result if result else '(empty)'}")
        print(f"\nExpected:\n{expected if expected else '(empty)'}")
        print(f"\nResult matches expected: {result == expected}")

    finally:
        # Secure: Clean up the test file in a finally block to ensure it's removed.
        if os.path.exists(filename):
            os.remove(filename)
    print("---------------------\n")


if __name__ == "__main__":
    run_test_case(1, "name age\nalice 21\nryan 30", "name alice ryan\nage 21 30")
    run_test_case(2, "a b c d", "a\nb\nc\nd")
    run_test_case(3, "x\ny\nz", "x y z")
    run_test_case(4, "1 2 3\n4 5 6\n7 8 9", "1 4 7\n2 5 8\n3 6 9")
    run_test_case(5, "", "")