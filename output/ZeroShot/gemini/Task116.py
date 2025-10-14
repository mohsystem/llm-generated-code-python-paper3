import os
import sys
import pwd
import grp
import re

# This program is designed for POSIX-compliant systems (like Linux, macOS)
# and must be run with root privileges (e.g., `sudo python your_script.py`).
# It will not work on Windows.

def change_user_password(username, new_password):
    """
    Performs the privileged operation of changing a user's password.
    This is a simulation. A real implementation would use a more secure
    method like `subprocess` with `passwd --stdin`.
    """
    if os.geteuid() != 0:
        print("Error: This operation requires root privileges.", file=sys.stderr)
        return False

    # Secure coding: Validate username to prevent command injection.
    if not re.match(r"^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,30}$", username):
        print(f"Error: Invalid username format for '{username}'.", file=sys.stderr)
        return False
    
    if not new_password:
        print("Error: Password cannot be empty.", file=sys.stderr)
        return False

    print(f"[PRIVILEGED] Simulating password change for user '{username}'...")
    # In a real scenario, you might use:
    # import subprocess
    # process = subprocess.run(['passwd', '--stdin', username], input=f'{new_password}\n', text=True)
    # if process.returncode != 0:
    #     print(f"Failed to change password for {username}.", file=sys.stderr)
    #     return False
    print(f"[PRIVILEGED] Password for '{username}' successfully changed.")
    return True

def drop_privileges():
    """
    Drops root privileges to the user who invoked sudo.
    """
    if os.geteuid() != 0:
        print("Not running as root. No privileges to drop.")
        return False

    try:
        # Get the UID and GID of the user who called sudo
        target_uid = int(os.environ.get('SUDO_UID', '-1'))
        target_gid = int(os.environ.get('SUDO_GID', '-1'))
        
        if target_uid == -1 or target_gid == -1:
            print("Error: SUDO_UID or SUDO_GID not set. Cannot drop privileges.", file=sys.stderr)
            return False

        print(f"\nDropping privileges to UID={target_uid}, GID={target_gid}...")

        # Set the group ID first
        os.setgid(target_gid)
        
        # Set the user ID
        os.setuid(target_uid)

        print("Successfully dropped privileges.")
        return True
    except (PermissionError, ValueError) as e:
        print(f"Error: Failed to drop privileges: {e}", file=sys.stderr)
        return False

def attempt_read_shadow():
    """Attempts to read a root-only file to verify privilege drop."""
    print("\nAttempting to read /etc/shadow as non-privileged user...")
    try:
        with open('/etc/shadow', 'r') as f:
            f.readline()
        print("Success: Was able to read /etc/shadow. Privileges were NOT dropped correctly.")
    except PermissionError:
        print("Success: Permission denied as expected. Privileges dropped correctly.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root (use sudo).", file=sys.stderr)
        sys.exit(1)

    print(f"Script started with UID={os.geteuid()} GID={os.getegid()}")
    
    print("\n--- Running 5 Privileged Test Cases ---")
    change_user_password("testuser1", "Password123!")
    change_user_password("app_service", "SecurePass!@#")
    change_user_password("invalid;user", "password") # Should fail validation
    change_user_password("testuser2", "") # Should fail validation
    change_user_password("another_user", "GoodPa$$w0rd")

    print("\n--- All privileged operations complete ---")

    if drop_privileges():
        print(f"Script now running with UID={os.geteuid()} GID={os.getegid()}")
        attempt_read_shadow()
    else:
        print("Exiting due to failure in dropping privileges.", file=sys.stderr)
        sys.exit(1)