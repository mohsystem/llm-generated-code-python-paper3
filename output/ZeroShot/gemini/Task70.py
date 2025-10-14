import os
import sys
import pathlib
import shutil

# The allowed directory for file access (current working directory)
BASE_DIR = pathlib.Path.cwd().resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024 # 10 MB

def read_file_content(user_path: str) -> str:
    """
    Securely reads the content of a file specified by a path.
    The path is validated to prevent directory traversal attacks. The file must
    exist within the current working directory.

    Args:
        user_path: The path to the file provided by the user.

    Returns:
        The content of the file as a string, or an error message if the operation fails.
    """
    if not user_path:
        return "Error: File path cannot be empty."

    try:
        # Create a Path object from the user input
        requested_path = pathlib.Path(user_path)

        # Resolve the path to get its absolute, canonical form, resolving symlinks.
        # This is a crucial security step.
        # We join with BASE_DIR to handle relative paths correctly.
        absolute_requested_path = (BASE_DIR / requested_path).resolve()

        # Security Check 1: Ensure the resolved path is within the allowed base directory.
        # For Python 3.9+, you can use: `absolute_requested_path.is_relative_to(BASE_DIR)`
        if BASE_DIR.as_posix() not in absolute_requested_path.as_posix():
             return "Error: Directory traversal attempt detected. Access denied."

        # Security Check 2: Ensure the path points to a regular file.
        if not absolute_requested_path.is_file():
            if absolute_requested_path.exists():
                return "Error: Path does not point to a regular file."
            else:
                return "Error: File does not exist."
        
        # Security Check 3: Check file size to prevent DoS
        if absolute_requested_path.stat().st_size > MAX_FILE_SIZE:
            return "Error: File is too large."

        # Read the file content
        return absolute_requested_path.read_text(encoding='utf-8')

    except (PermissionError, UnicodeDecodeError) as e:
        return f"Error: Cannot read file. {e}"
    except Exception as e:
        # Catch other potential errors (e.g., path contains null bytes)
        return f"Error: An unexpected error occurred. {e}"


def main():
    """Main function to handle command-line arguments and run test cases."""
    # Handle command-line argument if provided
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"Reading file from command line argument: {file_path}")
        content = read_file_content(file_path)
        print("--- File Content ---")
        print(content)
        print("--- End of Content ---")
        return # Exit after processing command-line arg

    # Setup for integrated test cases
    print("Running integrated test cases...")
    test_sub_dir = pathlib.Path("test_dir")
    safe_file = pathlib.Path("safe.txt")
    nested_file = test_sub_dir / "nested.txt"
    
    try:
        # Create test files and directories
        test_sub_dir.mkdir(exist_ok=True)
        safe_file.write_text("This is a safe file.", encoding='utf-8')
        nested_file.write_text("This is a nested file.", encoding='utf-8')
        
        # --- Test Cases ---
        print("\n--- Test Case 1: Valid file in CWD ---")
        print(f"Input: {safe_file}")
        print(f"Output: \n{read_file_content(str(safe_file))}")
        
        print("\n--- Test Case 2: Valid nested file ---")
        print(f"Input: {nested_file}")
        print(f"Output: \n{read_file_content(str(nested_file))}")

        print("\n--- Test Case 3: Path Traversal attempt ---")
        traversal_path = "../safe.txt"
        print(f"Input: {traversal_path}")
        print(f"Output: \n{read_file_content(traversal_path)}")

        print("\n--- Test Case 4: Non-existent file ---")
        non_existent_file = "nonexistent.txt"
        print(f"Input: {non_existent_file}")
        print(f"Output: \n{read_file_content(non_existent_file)}")

        print("\n--- Test Case 5: Attempt to read a directory ---")
        print(f"Input: {test_sub_dir}")
        print(f"Output: \n{read_file_content(str(test_sub_dir))}")

    except Exception as e:
        print(f"Failed to run test environment: {e}", file=sys.stderr)
    finally:
        # Clean up created files and directories
        if safe_file.exists():
            safe_file.unlink()
        if test_sub_dir.exists():
            shutil.rmtree(test_sub_dir)

if __name__ == "__main__":
    main()