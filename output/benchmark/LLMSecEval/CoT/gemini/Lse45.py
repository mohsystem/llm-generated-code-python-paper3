import os
import pathlib

# Define the safe directory. In a real application, this should be an absolute path.
SAFE_DIRECTORY = "safe_dir"

def read_file_from_safe_directory(filename: str) -> str:
    """
    Reads a file from a predefined safe directory.
    Prevents path traversal attacks by resolving the canonical path of the
    requested file and ensuring it is a descendant of the safe directory.

    Args:
        filename: The name of the file to read. Subdirectories are allowed.

    Returns:
        The content of the file as a string.
    
    Raises:
        SecurityException: If a path traversal attack is detected.
        FileNotFoundError: If the file does not exist.
        IOError: For other file reading errors.
    """
    try:
        # Resolve the absolute path of the safe directory
        safe_dir_path = pathlib.Path(SAFE_DIRECTORY).resolve(strict=True)
        
        # Construct the target file path and resolve it to its absolute path.
        # Resolving the path canonicalizes it (e.g., handles '..').
        target_file_path = (safe_dir_path / filename).resolve(strict=True)

        # Security Check: Use is_relative_to (Python 3.9+) for a robust check.
        # For older Python, you would check if the safe_dir_path is a parent.
        # if not str(target_file_path).startswith(str(safe_dir_path)):
        # The check below is more robust and preferred.
        if not target_file_path.is_relative_to(safe_dir_path):
             # This case should theoretically not be reached due to how resolve() works
             # with strict=True, but it's a good defense-in-depth measure.
            raise SecurityException(f"Access Denied: Path traversal attempt detected for file: {filename}")

        if not target_file_path.is_file():
             raise FileNotFoundError(f"Path does not point to a regular file: {filename}")
             
        return target_file_path.read_text()

    except FileNotFoundError:
        # This catches cases where the file or an intermediate directory doesn't exist.
        # This also catches the traversal attempt '../evil.txt' because resolving it
        # with strict=True from inside safe_dir will fail if safe_dir/../evil.txt doesn't exist.
        # It's better to give a generic error to avoid leaking path information.
        raise FileNotFoundError(f"File not found or access denied: {filename}")
    except Exception as e:
        # Re-raise other unexpected errors.
        raise e


# Custom exception for security violations
class SecurityException(Exception):
    pass

def main():
    """Sets up a test environment and runs test cases."""
    print("--- Setting up test environment ---")
    safe_dir = pathlib.Path(SAFE_DIRECTORY)
    # Clean up previous runs
    if safe_dir.exists():
        import shutil
        shutil.rmtree(safe_dir)
        
    safe_dir.mkdir()
    (safe_dir / "sub").mkdir()
    (safe_dir / "good_file.txt").write_text("This is a safe file.")
    (safe_dir / "sub" / "nested_file.txt").write_text("This is a nested safe file.")
    
    evil_file = pathlib.Path("evil.txt")
    evil_file.write_text("This file is outside the safe directory.")
    print("Setup complete.\n")

    # --- Test Cases ---
    test_cases = [
        "good_file.txt",            # 1. Should succeed
        "sub/nested_file.txt",      # 2. Should succeed (subdirectory)
        "non_existent.txt",         # 3. Should fail (not found)
        "../evil.txt",              # 4. Should fail (path traversal)
        "sub/../../evil.txt"        # 5. Should fail (complex path traversal)
    ]

    print("--- Running Test Cases ---")
    for test_case in test_cases:
        print(f"Attempting to read: '{test_case}'")
        try:
            content = read_file_from_safe_directory(test_case)
            print(f"  [SUCCESS] Content: \"{content}\"")
        except (SecurityException, FileNotFoundError, IOError) as e:
            print(f"  [FAILURE] {type(e).__name__}: {e}")
        print("---------------------------------")
        
    # --- Cleanup ---
    if evil_file.exists():
        evil_file.unlink()

if __name__ == "__main__":
    main()