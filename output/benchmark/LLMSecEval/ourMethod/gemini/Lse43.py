import os
import stat
import tempfile
import pathlib
import sys
import shutil

# In a real application, this would be a hardcoded, secured path like "/safe".
# For this example, we create a temporary directory to ensure it can run anywhere.
SAFE_DIRECTORY = os.path.join(tempfile.gettempdir(), "safe_py")

MAX_FILE_SIZE = 1024 * 1024  # 1 MB limit
BUFFER_SIZE = 8192

def read_file_from_safe_directory(filename: str) -> bytes | None:
    """
    Securely reads a file from a designated safe directory using the
    open-then-validate pattern.
    """
    # Rule #4, #7: Input validation. Reject path components and null bytes.
    if not filename or "/" in filename or "\\" in filename or "\0" in filename:
        print(f"Error: Invalid characters in filename '{filename}'.", file=sys.stderr)
        return None
    
    if os.path.basename(filename) != filename:
        print(f"Error: Path components detected in filename '{filename}'.", file=sys.stderr)
        return None

    dir_fd = -1
    fd = -1
    try:
        # Open the trusted base directory to anchor our operations
        dir_fd = os.open(SAFE_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY)

        # Rule #3: Open the resource first in a race-safe way.
        # os.O_NOFOLLOW prevents following symbolic links.
        # os.O_CLOEXEC prevents fd leakage to child processes.
        flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | os.O_NOFOLLOW
        fd = os.open(filename, flags, dir_fd=dir_fd)

        # Rule #3: Validate the already-opened handle (file descriptor).
        st = os.fstat(fd)

        # Rule #4: Reject if not a regular file.
        if not stat.S_ISREG(st.st_mode):
            print(f"Error: '{filename}' is not a regular file.", file=sys.stderr)
            return None

        # Rule #1: Reject if size exceeds policy.
        if st.st_size > MAX_FILE_SIZE:
            print(f"Error: '{filename}' is too large ({st.st_size} bytes).", file=sys.stderr)
            return None

        # Rule #1: Read from the validated handle.
        content = bytearray()
        while True:
            chunk = os.read(fd, BUFFER_SIZE)
            if not chunk:
                break
            
            # Check size on each read to prevent TOCTOU file growth attacks
            if len(content) + len(chunk) > MAX_FILE_SIZE:
                 print(f"Error: File '{filename}' grew beyond size limit during read.", file=sys.stderr)
                 return None
            content.extend(chunk)
        
        return bytes(content)

    except FileNotFoundError:
        print(f"Error: File not found: '{filename}'.", file=sys.stderr)
        return None
    except (IsADirectoryError, PermissionError):
        print(f"Error: Path is a directory or lacks permissions: '{filename}'.", file=sys.stderr)
        return None
    except OSError as e:
        # ELOOP is a hard failure for symlink loops with O_NOFOLLOW
        print(f"Error opening or reading file '{filename}': {e}", file=sys.stderr)
        return None
    finally:
        # Rule #5: Ensure resources are closed.
        if fd != -1:
            os.close(fd)
        if dir_fd != -1:
            os.close(dir_fd)

def setup_test_environment():
    """Create a temporary /safe directory and test files."""
    if os.path.exists(SAFE_DIRECTORY):
        shutil.rmtree(SAFE_DIRECTORY)
    
    safe_path = pathlib.Path(SAFE_DIRECTORY)
    safe_path.mkdir(parents=True, exist_ok=True)
    
    (safe_path / "goodfile.txt").write_text("hello world")
    
    outside_file = safe_path.parent / "outside.txt"
    outside_file.write_text("secret")
    
    symlink_path = safe_path / "symlink.txt"
    if symlink_path.exists():
        symlink_path.unlink()
    
    # symlink_to is not available on all Windows versions with Python < 3.8
    if hasattr(os, "symlink"):
        os.symlink(outside_file, symlink_path)
    else:
        print("Warning: symlink creation not supported; skipping symlink test.", file=sys.stderr)


    (safe_path / "subdir").mkdir(exist_ok=True)
    

def main():
    setup_test_environment()
    print("--- Running Test Cases ---")
    print(f"Using safe directory: {SAFE_DIRECTORY}")

    print("\n1. Reading 'goodfile.txt' (should succeed):")
    content = read_file_from_safe_directory("goodfile.txt")
    if content is not None:
        print(f"Success! Content: {content.decode('utf-8')}")
    else:
        print("Failed.")

    print("\n2. Reading 'nonexistent.txt' (should fail):")
    content = read_file_from_safe_directory("nonexistent.txt")
    if content is None:
        print("Success! Read failed as expected.")
    else:
        print("Failed. Read should not have succeeded.")

    if os.path.lexists(os.path.join(SAFE_DIRECTORY, "symlink.txt")):
        print("\n3. Reading 'symlink.txt' (should fail):")
        content = read_file_from_safe_directory("symlink.txt")
        if content is None:
            print("Success! Symlink read failed as expected.")
        else:
            print("Failed. Symlink should have been rejected.")
    
    print("\n4. Reading '../.../goodfile.txt' (should fail):")
    traversal_path = os.path.join("..", os.path.basename(SAFE_DIRECTORY), "goodfile.txt")
    content = read_file_from_safe_directory(traversal_path)
    if content is None:
        print("Success! Path traversal failed as expected.")
    else:
        print("Failed. Path traversal should have been blocked.")
        
    print("\n5. Reading 'subdir' (should fail):")
    content = read_file_from_safe_directory("subdir")
    if content is None:
        print("Success! Reading a directory failed as expected.")
    else:
        print("Failed. Directory should not be readable as a file.")

if __name__ == "__main__":
    main()