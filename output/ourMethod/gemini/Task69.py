import sys
import os
from pathlib import Path

def delete_file(file_path: str) -> bool:
    """
    Deletes a file at the given path after performing security checks.
    It will not delete directories or symbolic links.

    Args:
        file_path: The path to the file to be deleted.

    Returns:
        True if the file was successfully deleted, False otherwise.
    """
    if not file_path:
        print("Error: File path cannot be empty.", file=sys.stderr)
        return False

    try:
        p = Path(file_path)

        # Security Check: Do not follow symbolic links for checks.
        # This helps mitigate TOCTOU vulnerabilities.
        if p.is_symlink():
            print(f"Error: Deleting symbolic links is not allowed. Path: {file_path}", file=sys.stderr)
            return False
        
        if not p.exists():
            print(f"Error: File does not exist. Path: {file_path}", file=sys.stderr)
            return False

        if p.is_dir():
            print(f"Error: Path is a directory, not a file. Path: {file_path}", file=sys.stderr)
            return False

        if not p.is_file():
            print(f"Error: Path is not a regular file. Path: {file_path}", file=sys.stderr)
            return False

        p.unlink()
        print(f"Successfully deleted file: {file_path}")
        return True

    except PermissionError:
        print(f"Error: Permission denied. Could not delete file: {file_path}", file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: File not found for deletion. Path: {file_path}", file=sys.stderr)
    except IsADirectoryError:
        print(f"Error: Path is a directory. Cannot delete: {file_path}", file=sys.stderr)
    except OSError as e:
        print(f"An OS error occurred: {e}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    
    return False

def run_test(test_name: str, path: str):
    """Helper function to run a single test case."""
    print(f"--- {test_name} ---")
    print(f"Attempting to delete: {path}")
    delete_file(path)
    print()

def main():
    """
    Main function to handle command-line arguments or run test cases.
    """
    if len(sys.argv) == 2:
        delete_file(sys.argv[1])
    else:
        print(f"Usage: python {sys.argv[0]} <file_path>")
        print("\n--- No file path provided, running built-in test cases ---")

        test_file = Path("test_file_python.txt")
        test_dir = Path("test_dir_python")
        test_link = Path("test_link_python.txt")
        non_existent_file = Path("non_existent_file.txt")

        # Cleanup before setup
        for p in [test_file, test_dir, test_link]:
            try:
                if p.is_symlink() or p.is_file(): p.unlink()
                elif p.is_dir(): p.rmdir()
            except FileNotFoundError:
                pass
        
        try:
            test_file.touch()
            test_dir.mkdir()
            try:
                os.symlink(test_file, test_link)
            except (OSError, AttributeError, NotImplementedError) as e:
                print(f"Warning: Could not create symbolic link for test. {e}", file=sys.stderr)

            # --- 5 Test Cases ---
            run_test("Test Case 1: Delete existing file", str(test_file))
            run_test("Test Case 2: Delete non-existent file", str(non_existent_file))
            run_test("Test Case 3: Delete a directory", str(test_dir))
            if test_link.is_symlink():
                run_test("Test Case 4: Delete a symbolic link", str(test_link))
            else:
                print("--- Skipping Test Case 4: Symbolic link was not created ---\n")
            run_test("Test Case 5: Re-delete already deleted file", str(test_file))
        
        finally:
            # Cleanup
            if test_dir.exists(): test_dir.rmdir()
            if test_link.is_symlink(): test_link.unlink()
            if test_file.exists(): test_file.unlink()
            print("--- Test cleanup complete ---")

if __name__ == "__main__":
    main()