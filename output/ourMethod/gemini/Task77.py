import sys
import os
import ftplib
import ssl
import argparse
import tempfile
from typing import Optional

def create_secure_ssl_context() -> ssl.SSLContext:
    """
    Creates a secure SSL context that enforces TLS 1.2+ and requires
    certificate validation. This aligns with modern security best practices.
    """
    # Rules#1, #2, #6: Use vetted libraries and modern algorithms.
    # Enforce TLS 1.2+ and never disable certificate validation.
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    # Enforce TLS 1.2 or higher
    # The following block is from the official Python SSL documentation
    # and security best practices for disabling older, insecure protocols.
    if hasattr(ssl, "TLSVersion"):  # Python 3.10+
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:  # Older Python versions
        # Block insecure protocols
        context.options |= getattr(ssl, "OP_NO_SSLv2", 0)
        context.options |= getattr(ssl, "OP_NO_SSLv3", 0)
        context.options |= getattr(ssl, "OP_NO_TLSv1", 0)
        context.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)

    return context

def download_file_ftps(hostname: str, username: str, password: str, remote_path: str, local_filename: str) -> bool:
    """
    Connects to an FTPS server, logs in, and securely downloads a file.

    Args:
        hostname: The hostname or IP address of the FTPS server.
        username: The username for authentication.
        password: The password for authentication.
        remote_path: The full path of the file to download on the server.
        local_filename: The name to save the file as locally.

    Returns:
        True if the download was successful, False otherwise.
    """
    # Rule #11: Validate and sanitize all external input used in path construction.
    # Use os.path.basename to prevent path traversal attacks.
    sanitized_local_filename = os.path.basename(local_filename)
    if not sanitized_local_filename:
        print(f"Error: Invalid local filename '{local_filename}' provided.", file=sys.stderr)
        return False
    
    # Rule #12: Validate inputs.
    if not all([hostname, username, password, remote_path]):
        print("Error: Hostname, username, password, and remote path cannot be empty.", file=sys.stderr)
        return False

    context = create_secure_ssl_context()
    ftp = None
    temp_filename = None

    try:
        # Use FTP_TLS for explicit FTPS (FTP over SSL/TLS).
        ftp = ftplib.FTP_TLS(context=context, timeout=30)
        ftp.connect(hostname, 21)
        ftp.login(username, password)
        # Switch to secure data connection
        ftp.prot_p()

        # Rule #15: Mitigate TOCTOU vulnerabilities. Write to a temporary file
        # and then atomically rename it to the final destination.
        # Create temp file in the current directory to ensure atomic rename.
        with tempfile.NamedTemporaryFile(mode='wb', dir='.', delete=False) as temp_file:
            temp_filename = temp_file.name
            print(f"Downloading '{remote_path}' to temporary file '{temp_filename}'...")
            ftp.retrbinary(f'RETR {remote_path}', temp_file.write)
        
        # Atomically rename the temporary file to the final destination.
        os.rename(temp_filename, sanitized_local_filename)
        temp_filename = None # Prevent deletion in the finally block
        print(f"Successfully downloaded and saved to '{sanitized_local_filename}'")
        return True

    # Rule #17: Ensure that all exceptions are caught and handled appropriately.
    except ftplib.all_errors as e:
        print(f"FTP Error: {e}", file=sys.stderr)
        return False
    except IOError as e:
        print(f"File I/O Error: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False
    finally:
        if ftp:
            try:
                ftp.quit()
            except ftplib.all_errors:
                # Ignore errors during quit as we are already handling a failure.
                pass
        # Clean up the temporary file if an error occurred after its creation
        if temp_filename and os.path.exists(temp_filename):
            os.remove(temp_filename)

def main():
    """
    Parses command-line arguments and initiates the FTPS file download.
    """
    parser = argparse.ArgumentParser(
        description="Securely download a file from an FTPS server. "
                    "The password must be provided via the FTP_PASSWORD environment variable.",
        epilog="Example: python your_script.py ftps.example.com user /remote/file.txt local.txt"
    )
    parser.add_argument("hostname", help="FTPS server hostname.")
    parser.add_argument("username", help="FTPS username.")
    parser.add_argument("remote_path", help="Full path to the remote file to download.")
    parser.add_argument("local_filename", help="Filename to save the file as locally.")

    # In a real scenario, command-line arguments might not be available.
    # For testing purposes, we check if we're running interactively with no args.
    if len(sys.argv) == 1:
        # The prompt requires test cases. As a live FTPS server is needed,
        # these test cases demonstrate usage rather than being self-executing.
        print("--- Test Case Examples ---")
        print("This script requires command-line arguments to run.")
        print("The following are 5 examples of how to invoke it.")
        print("Note: A live, properly configured FTPS server is required for these to work.\n")

        test_cases = [
            # 1. Standard valid case
            ("ftps.example.com", "user1", "/path/to/report.csv", "local_report.csv"),
            # 2. Another valid case with different file type
            ("secureftp.corp.net", "data_user", "/exports/archive.zip", "archive.zip"),
            # 3. Path traversal attempt (will be sanitized to 'malicious.txt')
            ("ftps.example.com", "user1", "/sensitive/data.txt", "../../../malicious.txt"),
            # 4. Non-existent remote file (should result in an FTP error)
            ("ftps.example.com", "user1", "/path/to/nonexistent_file.dat", "error_file.dat"),
            # 5. Invalid hostname (should result in a connection error)
            ("invalid-hostname-that-does-not-exist.local", "user1", "/file.txt", "file.txt"),
        ]

        for i, (host, user, r_path, l_file) in enumerate(test_cases, 1):
            print(f"--- Test Case {i} ---")
            print(f"Description: Simulating download from '{host}' for file '{r_path}'.")
            print("Command to run:")
            print(f"  export FTP_PASSWORD='your_secret_password'")
            print(f"  python {os.path.basename(__file__)} {host} {user} '{r_path}' '{l_file}'\n")
        return

    args = parser.parse_args()

    # Rules#3, #4: Use secure vaults or environment variables for credentials.
    # Avoid passing passwords as command-line arguments, which can be logged.
    password = os.getenv("FTP_PASSWORD")
    if not password:
        print("Error: FTP_PASSWORD environment variable not set.", file=sys.stderr)
        print("Please set it before running the script:", file=sys.stderr)
        print("  export FTP_PASSWORD='your_password'", file=sys.stderr)
        sys.exit(1)

    success = download_file_ftps(
        args.hostname,
        args.username,
        password,
        args.remote_path,
        args.local_filename
    )

    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()