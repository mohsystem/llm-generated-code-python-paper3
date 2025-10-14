import os
import shutil

# The base directory from which files can be served.
BASE_DIRECTORY = "public"

def retrieve_file_content(user_provided_filename: str) -> str or None:
    """
    Securely retrieves the content of a file from a predefined base directory.
    It prevents path traversal attacks by ensuring the requested file's canonical
    path is within the base directory.

    :param user_provided_filename: The name of the file provided by the user.
    :return: The file content as a string if successful, otherwise None.
    """
    if not user_provided_filename:
        print("Error: Filename cannot be empty.")
        return None

    try:
        base_dir = os.path.realpath(BASE_DIRECTORY)

        # Sanitize input: only consider the filename part, stripping any path.
        # This is a crucial step to prevent directory traversal.
        safe_filename = os.path.basename(user_provided_filename)
        
        full_path = os.path.join(base_dir, safe_filename)

        # Get the canonical (real) path of the target file.
        # This resolves any '..', '.', or symbolic links.
        real_full_path = os.path.realpath(full_path)

        # Security Check: The real path of the file must be within the real path of the base directory.
        # os.path.commonprefix is a robust way to check this on different OS.
        if os.path.commonprefix([real_full_path, base_dir]) != base_dir:
            print(f"Security Alert: Path traversal attempt detected for file: {user_provided_filename}")
            return None

        if os.path.exists(real_full_path) and os.path.isfile(real_full_path):
            with open(real_full_path, 'r', encoding='utf-8') as f:
                return f.read()
        else:
            print(f"Error: File not found or is a directory: {real_full_path}")
            return None

    except Exception as e:
        # Catches file not found, permissions errors, etc.
        print(f"Error retrieving file '{user_provided_filename}': {e}")
        return None

def main():
    """Main function with test cases"""
    # --- Test Setup ---
    if os.path.exists(BASE_DIRECTORY):
        shutil.rmtree(BASE_DIRECTORY)
    if os.path.exists("secret"):
        shutil.rmtree("secret")
        
    os.makedirs(os.path.join(BASE_DIRECTORY, "safe_dir"))
    os.makedirs("secret")
    with open(os.path.join(BASE_DIRECTORY, "file1.txt"), "w") as f:
        f.write("This is file 1.")
    with open(os.path.join(BASE_DIRECTORY, "safe_dir", "file2.txt"), "w") as f:
        f.write("This is file 2.")
    with open(os.path.join("secret", "secret.txt"), "w") as f:
        f.write("This is a secret.")
    print("Test environment created successfully.")

    # --- Test Cases ---
    test_cases = [
        "file1.txt",                             # 1. Valid file
        "safe_dir/file2.txt",                    # 2. Valid file in subdir (should fail due to basename sanitization)
        "../secret/secret.txt",                  # 3. Path Traversal
        "C:\\Windows\\System32\\drivers\\etc\\hosts" if os.name == 'nt' else "/etc/passwd", # 4. Absolute Path
        "nonexistent.txt"                        # 5. Non-existent file
    ]

    for i, test_case in enumerate(test_cases):
        print(f"\n--- Test Case {i + 1}: Requesting '{test_case}' ---")
        content = retrieve_file_content(test_case)
        if content:
            print(f"Success! File content:\n{content}")
        else:
            print("Failed as expected.")

    # --- Cleanup ---
    shutil.rmtree(BASE_DIRECTORY)
    shutil.rmtree("secret")
    print("\nTest environment cleaned up.")

if __name__ == "__main__":
    main()