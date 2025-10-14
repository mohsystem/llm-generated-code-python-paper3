import os
import sys

def simulate_password_change(username, password):
    """
    Simulates a privileged operation.
    Checks the effective user ID to determine if it can proceed.
    """
    if os.geteuid() == 0:
        print(f"PRIVILEGED: Successfully changed password for user '{username}'.")
        return True
    else:
        print(f"FAILED: Insufficient privileges to change password for user '{username}'.")
        return False

def drop_privileges_and_run(username, password):
    """
    Performs a privileged action, drops privileges, and then attempts the action again.
    """
    print(f"--- Starting process for user '{username}' ---")
    try:
        initial_euid = os.geteuid()
        print(f"Initial Effective User ID: {initial_euid}")

        if initial_euid != 0:
            print("Error: This program must be run as root (or with sudo).")
            print("Cannot perform privileged operations or drop privileges.")
            print("--- Process finished ---\n")
            return

        # 1. Perform privileged operation
        print("\nStep 1: Performing action with root privileges.")
        simulate_password_change(username, password)

        # 2. Drop privileges to the user who invoked sudo
        print("\nStep 2: Dropping root privileges.")
        target_uid_str = os.environ.get('SUDO_UID')
        target_gid_str = os.environ.get('SUDO_GID')

        if target_uid_str is None or target_gid_str is None:
            print("Error: SUDO_UID or SUDO_GID not found. Cannot drop privileges to original user.")
            print("--- Process finished ---\n")
            return

        target_uid = int(target_uid_str)
        target_gid = int(target_gid_str)
        
        print(f"Dropping to UID={target_uid}, GID={target_gid}")

        # IMPORTANT: Set group first, then user.
        os.setgid(target_gid)
        os.setuid(target_uid)

        final_euid = os.geteuid()
        print(f"Privileges dropped. New Effective User ID: {final_euid}")
        
        if final_euid == 0:
             print("WARNING: Failed to drop privileges.")
        else:
             print("SUCCESS: Privileges dropped successfully.")

        # 3. Attempt privileged operation again
        print("\nStep 3: Attempting the same action without root privileges.")
        simulate_password_change(username, password)
        
    except PermissionError as e:
        print(f"Caught expected error after dropping privileges: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        print("--- Process finished ---\n")

class Task116:
    @staticmethod
    def main():
        print("Running Privilege Drop Demonstration in Python")
        print("NOTE: This script must be executed with 'sudo'.\n")
        
        users_to_update = ["alice", "bob", "charlie", "david", "eve"]
        for i, user in enumerate(users_to_update):
            print(f"--- Test Case {i+1} ---")
            drop_privileges_and_run(user, "new_secure_password_123")

if __name__ == "__main__":
    Task116.main()