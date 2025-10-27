import os
import stat

def create_secret_file(file_name, content):
    """
    Creates a file, writes content to it, and changes its permissions
    to read-only for the owner. This uses POSIX-style permissions.

    :param file_name: The name of the file to create.
    :param content: The super secret info to write to the file.
    :return: The name of the file created, or None on failure.
    """
    try:
        # 1. & 2. Create a file and write the super secret info to it.
        with open(file_name, 'w') as f:
            f.write(content)

        # 3. Change permissions to read-only for the owner (r-------- or 400).
        # stat.S_IRUSR is the constant for owner-read permission.
        os.chmod(file_name, stat.S_IRUSR)

        # 4. Print the name of the file to the screen.
        print(file_name)
        return file_name
    except (IOError, OSError) as e:
        print(f"An error occurred while processing {file_name}: {e}")
        return None

def main():
    print("--- Running Python Test Cases ---")
    for i in range(5):
        file_name = f"python_secret_file_{i}.txt"
        secret_info = f"This is Python secret #{i}. The key is 42."
        print("Created file: ", end="")
        create_secret_file(file_name, secret_info)
    print("-----------------------------\n")

if __name__ == "__main__":
    main()