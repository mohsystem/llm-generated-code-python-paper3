
import os
import sys
from pathlib import Path
from typing import Optional


def delete_file(file_path: str) -> bool:
    """\n    Safely delete a file with path validation and security checks.\n    \n    Args:\n        file_path: The path to the file to delete\n        \n    Returns:\n        True if deletion was successful, False otherwise\n    """
    if not file_path or not file_path.strip():
        print("Error: File path is null or empty", file=sys.stderr)
        return False
    
    try:
        base_dir = Path.cwd().resolve()
        target_path = Path(file_path).resolve()
        
        if not str(target_path).startswith(str(base_dir)):
            print("Error: Path traversal attempt detected", file=sys.stderr)
            return False
        
        if not target_path.exists():
            print("Error: File does not exist", file=sys.stderr)
            return False
        
        if target_path.is_symlink():
            print("Error: Symbolic links are not allowed", file=sys.stderr)
            return False
        
        if target_path.is_dir():
            print("Error: Path is a directory, not a regular file", file=sys.stderr)
            return False
        
        if not target_path.is_file():
            print("Error: Not a regular file", file=sys.stderr)
            return False
        
        target_path.unlink()
        print(f"File deleted successfully: {target_path.name}")
        return True
        
    except ValueError as e:
        print("Error: Invalid path format", file=sys.stderr)
        return False
    except PermissionError as e:
        print("Error: Permission denied", file=sys.stderr)
        return False
    except OSError as e:
        print("Error: Cannot delete file", file=sys.stderr)
        return False
    except Exception as e:
        print("Error: Unexpected error occurred", file=sys.stderr)
        return False


def main() -> None:
    """Main entry point for the program."""
    if len(sys.argv) < 2:
        print("Test cases:")
        test_cases = [
            "test1.txt",
            "test2.txt",
            "../outside.txt",
            "test3.txt",
            ""
        ]
        
        for test_case in test_cases:
            print(f"\\nTest: {test_case if test_case else '(empty)'}")
            delete_file(test_case)
    else:
        delete_file(sys.argv[1])


if __name__ == "__main__":
    main()
