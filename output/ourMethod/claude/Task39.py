import os
from pathlib import Path
from typing import Optional

BASE_DIRECTORY = os.getcwd()


def display_file_contents(filename: str) -> str:
    """
    Safely display file contents without using system commands.

    Args:
        filename: The name of the file to display

    Returns:
        The file contents or an error message
    """
    if not filename or not filename.strip():
        return "Error: Filename cannot be null or empty"

    # Sanitize and validate the filename
    sanitized = filename.strip()

    # Reject path traversal attempts
    if ".." in sanitized or "/" in sanitized or "\\" in sanitized:
        return "Error: Invalid filename - path traversal not allowed"

    try:
        base_path = Path(BASE_DIRECTORY).resolve()
        file_path = (base_path / sanitized).resolve()

        # Ensure the resolved path is within the base directory
        if not str(file_path).startswith(str(base_path)):
            return "Error: Access denied - file outside allowed directory"

        # Check if file exists and is a regular file
        if not file_path.exists():
            return "Error: File does not exist"

        if not file_path.is_file():
            return "Error: Not a regular file"

        # Read file contents safely
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        return content

    except IOError as e:
        return f"Error: Unable to read file - {str(e)}"
    except PermissionError:
        return "Error: Permission denied"
    except Exception as e:
        return f"Error: {str(e)}"


def main() -> None:
    """Main function with test cases."""
    test_files = ["test1.txt", "test2.txt", "../etc/passwd", "test/file.txt", ""]

    print("=== File Content Display Program ===\n")

    for test_file in test_files:
        print(f"Attempting to read: '{test_file}'")
        result = display_file_contents(test_file)
        print(result)
        print("---")

    # Interactive mode
    user_input = input("\nEnter filename to display (or 'quit' to exit): ")

    if user_input.lower() != "quit":
        result = display_file_contents(user_input)
        print(f"\nFile contents:\n{result}")


if __name__ == "__main__":
    main()
