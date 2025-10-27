import os
import shutil

# Define the base directory. For testing, we use a temporary directory.
# In a real application, this would be a fixed path like "/safe/".
SAFE_DIR = "test_root/safe/"

def read_file_from_safe_directory(filename: str) -> str:
    """
    Reads a file from a designated "safe" directory, preventing path traversal.
    Args:
        filename: The name of the file to read. Must not contain path separators.
    Returns:
        The content of the file as a string, or an error message.
    """
    # 1. Initial validation: Filename should not contain path separators.
    if '/' in filename or '\\' in filename:
        return "Error: Invalid characters in filename. Path traversal attempt rejected."

    # Construct the full path
    target_path = os.path.join(SAFE_DIR, filename)

    try:
        # 2. Canonical path validation: Resolve '..' and symlinks to get the real path.
        # This is the most secure way to validate the path.
        real_safe_path = os.path.realpath(SAFE_DIR)
        real_target_path = os.path.realpath(target_path)

        # Ensure the target file's path is genuinely inside the safe directory.
        if not real_target_path.startswith(real_safe_path):
            return "Error: Path traversal attempt detected."

        # 3. Read the file if validation passes.
        with open(real_target_path, 'r', encoding='utf-8') as f:
            return f.read()

    except FileNotFoundError:
        return f"Error: Could not read file. File not found at '{os.path.abspath(target_path)}'"
    except Exception as e:
        return f"Error: Could not read file. {e}"

def main():
    """ Main function with test cases """
    # --- Test Environment Setup ---
    print("--- Setting up test environment ---")
    if os.path.exists("test_root"):
        shutil.rmtree("test_root")
    os.makedirs(SAFE_DIR)
    with open(os.path.join(SAFE_DIR, "good.txt"), "w") as f:
        f.write("This is a safe file.")
    with open(os.path.join(SAFE_DIR, "another.txt"), "w") as f:
        f.write("This is another safe file.")
    with open("test_root/outside.txt", "w") as f:
        f.write("This file is outside the safe directory.")
    print("Setup complete.")
    print("-------------------------------------\n")

    test_filenames = [
        "good.txt",  # Test Case 1: Valid file
        "another.txt", # Test Case 2: Another valid file
        "nonexistent.txt",  # Test Case 3: File does not exist
        "../outside.txt",  # Test Case 4: Path traversal attempt
        "good.txt/../../outside.txt"  # Test Case 5: Complex path traversal attempt
    ]

    for i, filename in enumerate(test_filenames):
        print(f"Test Case {i + 1}: Attempting to read '{filename}'")
        result = read_file_from_safe_directory(filename)
        print(f"Result: {result}\n")

    # --- Cleanup ---
    if os.path.exists("test_root"):
        shutil.rmtree("test_root")
    # print("Test environment cleaned up.")

if __name__ == "__main__":
    main()