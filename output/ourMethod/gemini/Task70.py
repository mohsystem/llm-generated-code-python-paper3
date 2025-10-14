import sys
import os
from pathlib import Path
import shutil

def read_file_content(file_path: str) -> str:
    """
    Reads the content of a file, ensuring the path is safe.

    :param file_path: The path to the file.
    :return: The content of the file as a string, or an error message on failure.
    """
    if not file_path:
        return "Error: File path is empty."
        
    try:
        user_path = Path(file_path)

        # Rule #7: Refuse symlinks.
        if user_path.is_symlink():
            return "Error: Symbolic links are not allowed."

        # Rule #7: Path must exist and be a file, not a directory.
        if not user_path.is_file():
            if not user_path.exists():
                return "Error: File does not exist."
            return "Error: Path does not point to a regular file."

        # Rule #7: Prevent path traversal attacks.
        # Resolve the path to its absolute canonical form.
        resolved_path = user_path.resolve()
        base_dir = Path.cwd().resolve()

        # Check if the resolved path is within the current working directory.
        if base_dir not in resolved_path.parents and resolved_path != base_dir:
            return "Error: Path traversal attempt detected."

        # Rule #1, #8: Safely read file using a context manager.
        with open(resolved_path, 'r', encoding='utf-8') as f:
            return f.read()

    except (IOError, OSError, SecurityException) as e:
        return f"Error reading file: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def run_tests():
    """Sets up a test environment and runs test cases."""
    print("Running test cases...")
    test_dir = Path("python_test_files")
    safe_file = test_dir / "safe_file.txt"
    sub_dir = test_dir / "sub"
    symlink_file = test_dir / "slink.txt"
    
    try:
        # Setup test environment
        test_dir.mkdir(exist_ok=True)
        sub_dir.mkdir(exist_ok=True)
        safe_file.write_text("This is a safe file.", encoding='utf-8')
        if not symlink_file.exists():
            os.symlink(safe_file.name, symlink_file)

        # Test Case 1: Read a valid file
        print("\n--- Test Case 1: Valid file ---")
        print(f"Reading: {safe_file}")
        print(f"Content: {read_file_content(str(safe_file))}")
        
        # Test Case 2: Read a non-existent file
        print("\n--- Test Case 2: Non-existent file ---")
        non_existent_path = str(test_dir / "nonexistent.txt")
        print(f"Reading: {non_existent_path}")
        print(f"Content: {read_file_content(non_existent_path)}")

        # Test Case 3: Attempt to read a directory
        print("\n--- Test Case 3: Directory path ---")
        print(f"Reading: {sub_dir}")
        print(f"Content: {read_file_content(str(sub_dir))}")

        # Test Case 4: Attempt to read a symbolic link
        print("\n--- Test Case 4: Symbolic link ---")
        print(f"Reading: {symlink_file}")
        print(f"Content: {read_file_content(str(symlink_file))}")

        # Test Case 5: Path traversal attempt
        print("\n--- Test Case 5: Path traversal ---")
        traversal_path = "../"
        print(f"Reading: {traversal_path}")
        print(f"Content: {read_file_content(traversal_path)}")

    except Exception as e:
        print(f"Test setup failed: {e}", file=sys.stderr)
    finally:
        # Cleanup
        if test_dir.exists():
            shutil.rmtree(test_dir)
            print("\nTest cleanup complete.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Process file path from command line argument
        content = read_file_content(sys.argv[1])
        print(content)
    else:
        # Run test cases if no arguments are provided
        run_tests()