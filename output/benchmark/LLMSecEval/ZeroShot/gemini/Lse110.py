import subprocess
import shlex

def run_id_command(username):
    """
    Runs the 'id <username>' command securely and returns its exit status.

    Args:
        username: The username to look up.

    Returns:
        The exit status of the 'id' command. 0 for success, non-zero for failure.
    """
    if not username:
        print("Error: Username cannot be empty.")
        return -1
        
    # Using a list of arguments for subprocess.run is the secure way to
    # execute commands. It avoids the shell and prevents command injection.
    command = ["id", username]
    
    try:
        # We capture stdout and stderr to prevent them from printing to the console
        result = subprocess.run(command, capture_output=True, check=False)
        return result.returncode
    except FileNotFoundError:
        print("Error: 'id' command not found. Is this a UNIX-like system?")
        return -1
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1


def main():
    """Main function with 5 test cases."""
    test_usernames = [
        "root",                 # A user that usually exists
        "daemon",               # Another user that often exists
        "nonexistentuser12345", # A user that should not exist
        "; whoami",             # A potential command injection attempt
        "test user"             # A username with a space
    ]
    
    print("--- Running 5 Test Cases ---")
    for user in test_usernames:
        print(f"Testing username: '{user}'")
        exit_status = run_id_command(user)
        print(f"Exit Status: {exit_status}\n")

if __name__ == "__main__":
    main()