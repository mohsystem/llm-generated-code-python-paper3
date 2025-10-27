import os
import stat

def handle_secret_file(filename, content):
    """
    Creates a file with restrictive permissions, writes content to it,
    and prints the final permissions. This uses POSIX-specific calls.

    Args:
        filename (str): The name of the file to create.
        content (str): The string content to write to the file.
    """
    print(f"Processing file: {filename}")
    file_descriptor = -1
    try:
        # 1 & 2. Create a file with restrictive permissions (600: owner read/write)
        # and open it for writing. This is an atomic operation and more secure
        # than creating and then changing permissions (avoids a race condition).
        # Note: The effective permissions will be (mode & ~umask).
        # A umask of 022 will result in 644, so we set it to 077 temporarily.
        original_umask = os.umask(0o077)
        file_descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.umask(original_umask) # Restore original umask
        
        # Write the content to the file.
        os.write(file_descriptor, content.encode('utf-8'))
        print(f"  - Successfully wrote to {filename} with restrictive permissions.")

    except OSError as e:
        print(f"  - Error processing file {filename}: {e}")
        return
    finally:
        if file_descriptor != -1:
            os.close(file_descriptor)

    try:
        # 3. Print the permissions of the file.
        file_stat = os.stat(filename)
        # stat.filemode converts the mode into a string like '-rw-------'
        permissions = stat.filemode(file_stat.st_mode)
        print(f"  - Final permissions: {permissions} ({oct(stat.S_IMODE(file_stat.st_mode))})")
    except OSError as e:
        print(f"  - Error reading permissions for {filename}: {e}")
    finally:
        print("------------------------------------")


if __name__ == "__main__":
    CONTENT = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    
    # 5 Test Cases
    handle_secret_file("secret1.txt", CONTENT)
    handle_secret_file("secret2.txt", CONTENT)
    handle_secret_file("secret3.txt", CONTENT)
    handle_secret_file("secret4.txt", CONTENT)
    handle_secret_file("secret5.txt", CONTENT)