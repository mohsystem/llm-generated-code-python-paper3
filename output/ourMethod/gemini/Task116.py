import os
import pwd
import grp
import sys
import re
from typing import List

# A pattern to validate usernames to be safe (alphanumeric, dashes, underscores)
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")

def change_user_password(username: str, new_password: str) -> None:
    """
    Simulates changing a user's password. This is the privileged part.
    In a real system, this would interact with `chpasswd` or a similar utility.
    """
    if os.geteuid() != 0:
        raise PermissionError("Must be root to change user passwords.")
    
    if not USERNAME_PATTERN.match(username):
        raise ValueError(f"Invalid username format: {username}")

    print(f"[PRIVILEGED] Simulating password change for user '{username}'.")
    # In a real scenario, you would securely call a command, e.g.,
    # import subprocess
    # proc = subprocess.run(['chpasswd'], input=f'{username}:{new_password}', text=True)
    # if proc.returncode != 0:
    #     raise RuntimeError("Failed to change password.")
    print("[PRIVILEGED] Privileged operation complete.")

def drop_privileges(username: str) -> None:
    """
    Drops root privileges to the specified user.
    """
    if os.geteuid() != 0:
        # This function is only meaningful if we start as root.
        print("Not running as root, no privileges to drop.")
        return

    if not USERNAME_PATTERN.match(username):
        raise ValueError(f"Invalid username format for privilege drop: {username}")

    try:
        pw = pwd.getpwnam(username)
        target_uid = pw.pw_uid
        target_gid = pw.pw_gid
    except KeyError:
        raise ValueError(f"User '{username}' not found.")

    print(f"--- Dropping privileges to user '{username}' (uid={target_uid}, gid={target_gid}) ---")

    # Set supplementary groups. initgroups() is important for security.
    os.initgroups(username, target_gid)

    # Set the group ID first
    os.setgid(target_gid)

    # Finally, set the user ID. After this, we cannot regain root privileges.
    os.setuid(target_uid)

    print(f"Privileges dropped. New effective UID: {os.geteuid()}")


def main():
    """Main function to demonstrate privilege dropping."""
    print("--- Privilege Drop Demonstration (Python) ---")
    print("NOTE: This script must be run with 'sudo' to demonstrate the full effect.\n")

    # The user to drop privileges to. 'nobody' is a common, unprivileged user.
    # On Debian/Ubuntu, 'nogroup' is the corresponding group. Use 'nobody' for others.
    drop_to_user = "nobody"
    try:
        pwd.getpwnam(drop_to_user)
    except KeyError:
        print(f"User '{drop_to_user}' not found. Exiting.")
        sys.exit(1)

    # --- Test Cases ---
    test_cases = [
        {"user": "testuser1", "pass": "Pass1!", "drop_user": drop_to_user},
        {"user": "app_user", "pass": "SecurePass_2", "drop_user": drop_to_user},
        {"user": ";reboot", "pass": "bad", "drop_user": drop_to_user}, # Invalid user
        {"user": "testuser3", "pass": "Pass3", "drop_user": "nonexistentuser"}, # Invalid drop user
        {"user": "another_user", "pass": "Pass4", "drop_user": drop_to_user}
    ]

    for i, tc in enumerate(test_cases):
        print(f"--- Test Case {i+1}: Change pass for '{tc['user']}', drop to '{tc['drop_user']}' ---")
        try:
            # Re-check UID at the start of each test case since the script will exit if
            # it successfully drops privileges. In a long-running daemon, this loop
            # wouldn't be structured this way. This is for demonstration.
            if os.geteuid() != 0:
                print("Cannot run test, not running as root.")
                break

            print(f"Initial effective UID: {os.geteuid()}")
            
            # 1. Perform privileged action
            change_user_password(tc["user"], tc["pass"])
            
            # 2. Drop privileges
            drop_privileges(tc["drop_user"])

            # 3. Attempt privileged action again (should fail)
            print("\nAttempting privileged action after dropping privileges...")
            change_user_password("anotheruser", "somepass")

        except (PermissionError, ValueError, RuntimeError) as e:
            print(f"Operation failed as expected: {e}")
        
        # In a real daemon, the program would continue here with reduced privileges.
        # For this script, we exit because we cannot regain privileges for the next test.
        if os.geteuid() != 0:
            print("\nExiting script because privileges have been dropped successfully.")
            break
        
        print("----------------------------------------------------------------\n")


if __name__ == "__main__":
    main()