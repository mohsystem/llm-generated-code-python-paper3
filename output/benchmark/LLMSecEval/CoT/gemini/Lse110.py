import sys
import subprocess

def run_id_command(username):
    """
    Runs the 'id <username>' command using the subprocess module.
    This approach is secure against command injection as arguments are passed
    as a list, preventing shell interpretation of special characters.

    Args:
        username: The username string to look up.

    Returns:
        The integer exit status of the command. 0 for success, non-zero for failure.
    """
    if not isinstance(username, str) or not username:
        print("Error: Username must be a non-empty string.", file=sys.stderr)
        return -1 # Indicate an error before even trying

    command = ["id", username]
    try:
        # subprocess.run is the recommended way to execute external commands.
        # It waits for the command to complete and returns a CompletedProcess object.
        # The command's output will be printed directly to the console by default.
        result = subprocess.run(command)
        return result.returncode
    except FileNotFoundError:
        print(f"Error: Command '{command[0]}' not found.", file=sys.stderr)
        return 127 # Standard exit code for command not found
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        return -1

def main():
    """
    Main function to handle command-line arguments or run test cases.
    """
    if len(sys.argv) > 1:
        # If a command-line argument is provided, use it.
        username = sys.argv[1]
        print(f"Running command: id {username}")
        exit_status = run_id_command(username)
        print(f"Exit Status: {exit_status}")
    else:
        # If no arguments are provided, run test cases.
        print("No command-line argument provided. Running test cases...")
        test_usernames = [
            "root",                                   # 1. Should succeed (exit 0) on most Unix-like systems.
            "nobody",                                 # 2. Should succeed (exit 0) on most Unix-like systems.
            "non_existent_user_12345",                # 3. Should fail (exit non-zero).
            "root;whoami",                            # 4. Malicious input; should be treated as a single, invalid username and fail.
            ""                                        # 5. Empty string, should be handled and fail.
        ]

        for user in test_usernames:
            print("\n------------------------------------")
            print(f"Testing with username: \"{user}\"")
            exit_status = run_id_command(user)
            print(f"Exit Status: {exit_status}")
            print("------------------------------------")

if __name__ == "__main__":
    main()