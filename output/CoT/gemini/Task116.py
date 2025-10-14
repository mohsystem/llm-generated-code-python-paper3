import os
import pwd
import grp
import subprocess
import sys

def perform_privileged_operation(username):
    """
    Performs an operation that requires root privileges.
    For this demo, we create a file in /root.
    """
    if os.geteuid() != 0:
        print("Error: This operation requires root privileges.", file=sys.stderr)
        return False
        
    print(f"[PRIVILEGED] Simulating password change for user: {username}")
    print("Attempting to create a test file in /root...")
    try:
        # Using subprocess is safer than os.system
        subprocess.run(
            ["touch", "/root/privilege_test_file.txt"],
            check=True,
            capture_output=True
        )
        print("Successfully created /root/privilege_test_file.txt")
        # Clean up the test file
        os.remove("/root/privilege_test_file.txt")
        print("Cleaned up test file.")
        return True
    except (subprocess.CalledProcessError, PermissionError) as e:
        print(f"Privileged operation failed as expected for non-root user: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False


def drop_privileges(user_name='nobody'):
    """
    Drops root privileges to the specified user.
    """
    if os.geteuid() != 0:
        # Not running as root, no privileges to drop
        print("Not running as root, no privileges to drop.")
        return

    try:
        # Get the UID and GID of the target user
        pwnam = pwd.getpwnam(user_name)
        target_uid = pwnam.pw_uid
        target_gid = pwnam.pw_gid

        print(f"\nAttempting to drop privileges to user '{user_name}' (UID: {target_uid}, GID: {target_gid})")

        # Remove all supplementary group privileges
        os.setgroups([])

        # Set the new group ID
        os.setgid(target_gid)

        # Set the new user ID
        os.setuid(target_uid)

        # Set a safe environment
        os.environ['HOME'] = pwnam.pw_dir
        os.environ['LOGNAME'] = pwnam.pw_name
        os.environ['USER'] = pwnam.pw_name
        
        print("Successfully dropped privileges.")
    except KeyError:
        print(f"Error: User '{user_name}' not found. Cannot drop privileges.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error: Failed to drop privileges: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    """ Main function with test cases """
    print("### Python Privilege Dropping Demonstration ###")

    # Test Case 1: Check if running as root
    if os.geteuid() != 0:
        print("This script must be run as root (using sudo) to demonstrate privilege dropping.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Initial state: Running as UID {os.getuid()}, GID {os.getgid()}")

    # Test Case 2: Perform a privileged operation successfully
    print("\n--- Test Case 2: Perform privileged operation as root ---")
    perform_privileged_operation("testuser1")

    # Test Case 3: Drop privileges
    print("\n--- Test Case 3: Dropping privileges ---")
    drop_privileges("nobody") # 'nobody' is a common unprivileged user
    print(f"Current state: Running as UID {os.getuid()}, GID {os.getgid()}")

    # Test Case 4: Attempt the same privileged operation, which should now fail
    print("\n--- Test Case 4: Attempt privileged operation after dropping privileges ---")
    if not perform_privileged_operation("testuser2"):
        print("Test passed: Privileged operation failed as expected.")

    # Test Case 5: The script ends here, but in a real daemon, it would
    # continue to run with these lowered privileges.
    print("\n--- Test Case 5: Script finished ---")
    print("The program would now continue running with reduced privileges.")

if __name__ == '__main__':
    main()