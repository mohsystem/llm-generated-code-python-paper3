import os
import random
import tempfile
import sys

def generate_and_write_to_file(filename: str) -> bool:
    """
    Generates three random floats, concatenates them into a string,
    and writes the string to a file securely.

    Args:
        filename: The name of the final file to write to.

    Returns:
        True if successful, False otherwise.
    """
    try:
        # 1. Generate 3 random floats and convert to a single string
        floats = [str(random.uniform(0.0, 1000.0)) for _ in range(3)]
        content = " ".join(floats)

        # 2. Write the string to a file using a secure, atomic operation
        target_path = os.path.abspath(filename)
        target_dir = os.path.dirname(target_path)

        os.makedirs(target_dir, exist_ok=True)

        # Create a temporary file securely. mkstemp is preferred as it's race-safe.
        # It returns a low-level file descriptor and an absolute path.
        # Permissions are set to 0o600 by default.
        fd, temp_path = tempfile.mkstemp(suffix=".tmp", prefix="data-", dir=target_dir)

        temp_file_obj = None
        try:
            # Use os.fdopen to wrap the file descriptor in a file object
            with os.fdopen(fd, 'w', encoding='utf-8') as temp_file_obj:
                temp_file_obj.write(content)
                # Ensure data is written to the kernel
                temp_file_obj.flush()
                # Ensure data is written to disk
                os.fsync(temp_file_obj.fileno())

            # Atomically rename the temp file to its final name.
            # os.replace is atomic on POSIX and Windows.
            os.replace(temp_path, target_path)
            return True
        except Exception:
            # On error, ensure the temporary file is removed
            if temp_file_obj is None and fd is not None:
                # If fdopen failed, close the raw descriptor
                 os.close(fd)
            # If temp_path was created, unlink it
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise # Re-raise the exception

    except (IOError, OSError) as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        return False


def main():
    """Runs 5 test cases."""
    print("Running 5 test cases...")
    for i in range(1, 6):
        file_name = f"output_python_{i}.txt"
        print(f"Test case {i}: Writing to {file_name}...", end="")
        success = generate_and_write_to_file(file_name)
        if success:
            print(" Succeeded.")
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    content = f.read()
                    print(f"  -> Content: {content}")
            except (IOError, OSError) as e:
                print(f"  -> Failed to read back file content: {e}", file=sys.stderr)
        else:
            print(" Failed.")


if __name__ == "__main__":
    main()