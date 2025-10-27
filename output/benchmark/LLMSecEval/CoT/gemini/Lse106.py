import os
import stat
import sys

def create_secret_file(file_name, secret_info):
    """
    Creates a file, writes secret info to it, and changes its permissions
    to be read-only for the file's owner.

    Args:
        file_name (str): The name of the file to create.
        secret_info (str): The secret content to write to the file.

    Returns:
        bool: True on success, False on failure.
    """
    try:
        # Create and write to the file using 'with' to ensure it's properly closed.
        with open(file_name, 'w') as f:
            f.write(secret_info)
        
        # Change permissions to read-only for the owner (0o400).
        # This is primarily for POSIX-compliant systems (Linux, macOS).
        # On Windows, this may have different effects or limitations.
        os.chmod(file_name, stat.S_IRUSR)
        
        print(f"Successfully created and secured file: {file_name}")
        return True
    except (IOError, OSError) as e:
        print(f"Error processing file '{file_name}': {e}", file=sys.stderr)
        return False

def main():
    """Main function with 5 test cases."""
    print("--- Python Test Cases ---")
    create_secret_file("secret_alpha.txt", "The launch code is 1234.")
    create_secret_file("secret_beta.log", "Meeting at midnight.")
    create_secret_file("secret_gamma.dat", "Alpha protocol is a go.")
    create_secret_file("top_secret.conf", "Password=SuperSecret!@#")
    create_secret_file("confidential_notes.txt", "This is a test of the emergency secret system.")
    print("-----------------------\n")

if __name__ == "__main__":
    main()