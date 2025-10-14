import re
import sys
from pathlib import Path
from typing import Optional

MAX_FILE_SIZE = 10_000_000  # 10MB limit
BASE_DIR = Path.cwd().resolve()


def search_file_with_pattern(pattern_str: str, file_name: str) -> str:
    """
    Search a file using a regular expression pattern.

    Args:
        pattern_str: Regular expression pattern string
        file_name: Name of the file to search

    Returns:
        String containing search results or error message
    """
    if not pattern_str:
        return "Error: Pattern cannot be empty"
    if not file_name:
        return "Error: File name cannot be empty"

    # Validate and sanitize file path
    try:
        base_path = BASE_DIR
        file_path = (base_path / file_name).resolve()

        # Ensure the resolved path is within base directory
        if not str(file_path).startswith(str(base_path)):
            return "Error: Access denied - path outside allowed directory"

        # Check if it's a regular file
        if not file_path.is_file():
            return "Error: Not a regular file"

        # Check file size
        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            return "Error: File too large (max 10MB)"

    except (OSError, ValueError) as e:
        return f"Error: Cannot access file - {str(e)}"
    except Exception as e:
        return f"Error: Invalid file path - {str(e)}"

    # Compile pattern
    try:
        pattern = re.compile(pattern_str)
    except re.error as e:
        return f"Error: Invalid regex pattern - {str(e)}"

    # Search file content
    result = []
    match_count = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, 1):
                line = line.rstrip("\n\r")
                if pattern.search(line):
                    match_count += 1
                    result.append(f"Line {line_number}: {line}")
    except OSError as e:
        return f"Error: Failed to read file - {str(e)}"

    if match_count == 0:
        return "No matches found"

    return f"Found {match_count} match(es):\n" + "\n".join(result)


def main():
    if len(sys.argv) == 3:
        pattern = sys.argv[1]
        file_name = sys.argv[2]
        print(search_file_with_pattern(pattern, file_name))
    else:
        # Test cases
        print("=== Test Case 1: Simple pattern ===")
        print(search_file_with_pattern("test", "testfile1.txt"))

        print("\n=== Test Case 2: Complex pattern ===")
        print(search_file_with_pattern(r"[0-9]{3}", "testfile2.txt"))

        print("\n=== Test Case 3: Invalid pattern ===")
        print(search_file_with_pattern("[invalid", "testfile1.txt"))

        print("\n=== Test Case 4: Non-existent file ===")
        print(search_file_with_pattern("test", "nonexistent.txt"))

        print("\n=== Test Case 5: Path traversal attempt ===")
        print(search_file_with_pattern("test", "../../../etc/passwd"))


if __name__ == "__main__":
    main()
