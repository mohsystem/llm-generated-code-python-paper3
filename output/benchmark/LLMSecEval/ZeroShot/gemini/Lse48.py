import os
import shutil
from pathlib import Path

def img(base_directory: str, file_name: str) -> bytes | None:
    """
    Securely reads a file from a base directory, preventing path traversal.

    :param base_directory: The secure directory from which files can be served.
    :param file_name: The name of the file requested by the user.
    :return: A bytes object of the file contents, or None if the file is not found,
             not accessible, or the request is insecure.
    """
    try:
        # Resolve the real, absolute paths
        base_dir_path = Path(base_directory).resolve(strict=True)
        requested_file_path = (base_dir_path / file_name).resolve(strict=True)

        # *** SECURITY CHECK ***
        # To prevent path traversal, check if the resolved requested path is a subpath
        # of the resolved base directory path.
        if base_dir_path not in requested_file_path.parents and requested_file_path != base_dir_path:
            print(f"Security alert: Path traversal attempt detected for file: {file_name}", flush=True)
            return None

        # Additional check to ensure it's a file and not a directory
        if not requested_file_path.is_file():
            # print(f"Error: Path is not a file: {requested_file_path}", flush=True)
            return None

        with open(requested_file_path, "rb") as f:
            return f.read()

    except (FileNotFoundError, NotADirectoryError, ValueError) as e:
        # ValueError can be raised by resolve() on Windows for invalid filenames
        # print(f"Error accessing file: {e}", flush=True)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", flush=True)
        return None

def run_test(test_name: str, base_dir: str, file_name: str):
    """Helper function to run and display test results"""
    print(f"--- Running Test: {test_name} ---")
    print(f"Requesting file: {file_name}")
    content = img(base_dir, file_name)
    if content:
        print(f"Result: SUCCESS - Read {len(content)} bytes.")
        # print(f"Content: {content.decode()}")
    else:
        print("Result: FAILED (or file securely blocked) - as expected for invalid cases.")
    print()

def main():
    """Main function to set up environment and run test cases."""
    base_dir = Path("safe_image_dir")
    unsafe_dir = Path("unsafe_dir")

    try:
        # Setup
        base_dir.mkdir(exist_ok=True)
        (base_dir / "subdir").mkdir(exist_ok=True)
        unsafe_dir.mkdir(exist_ok=True)

        (base_dir / "image1.jpg").write_text("jpeg_data_for_image1")
        (base_dir / "subdir" / "image2.png").write_text("png_data_for_image2")
        (unsafe_dir / "secret.txt").write_text("this is a secret file")
        
        # --- Test Cases ---
        # 1. Valid file in base directory
        run_test("Valid File", str(base_dir), "image1.jpg")

        # 2. Valid file in subdirectory
        run_test("Valid Subdirectory File", str(base_dir), "subdir/image2.png")

        # 3. Non-existent file
        run_test("Non-Existent File", str(base_dir), "notfound.gif")

        # 4. Path traversal attack
        traversal_path = os.path.join("..", str(unsafe_dir.name), "secret.txt")
        run_test("Path Traversal Attack", str(base_dir), traversal_path)

        # 5. Absolute path attack
        absolute_path = str(unsafe_dir.resolve() / "secret.txt")
        run_test("Absolute Path Attack", str(base_dir), absolute_path)
    
    finally:
        # Cleanup
        if base_dir.exists():
            shutil.rmtree(base_dir)
        if unsafe_dir.exists():
            shutil.rmtree(unsafe_dir)

if __name__ == "__main__":
    main()