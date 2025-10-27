import subprocess
import re
import sys

# Regex for a safe, typical POSIX username.
USERNAME_REGEX = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$')

def execute_id_command(username):
    """
    Executes the 'id' command for a given username in a secure way.

    Args:
        username: The username to look up.

    Returns:
        The exit code of the 'id' command, or a negative value on error.
        -1: Invalid username format.
        -2: 'id' command not found.
        -3: Command timed out.
        -4: Other unexpected error.
    """
    if not isinstance(username, str) or not USERNAME_REGEX.match(username):
        print(f"Error: Invalid username format provided for '{username}'.", file=sys.stderr)
        return -1  # Indicate invalid input

    try:
        # Using a list of arguments prevents shell injection (shell=False is default).
        # stdout and stderr are not captured, so they will be printed to the console.
        # A timeout is added for robustness.
        result = subprocess.run(["id", username], timeout=10)
        return result.returncode
    except FileNotFoundError:
        print("Error: 'id' command not found. Ensure you are on a POSIX-like system.", file=sys.stderr)
        return -2 # Indicate command not found
    except subprocess.TimeoutExpired:
        print(f"Error: Command 'id {username}' timed out.", file=sys.stderr)
        return -3 # Indicate timeout
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return -4 # Indicate other execution error

def main():
    """Main function to run test cases."""
    if len(sys.argv) > 1:
        # Handle command-line argument if provided
        print("--- Running with command-line argument ---")
        username = sys.argv[1]
        print(f"Running command for username: {username}")
        exit_status = execute_id_command(username)
        print(f"Exit Status: {exit_status}")
        print("----------------------------------------\n")

    print("--- Running 5 Hardcoded Test Cases ---")
    test_usernames = [
        "root",                 # Test case 1: Valid, existing user
        "daemon",               # Test case 2: Another valid, existing user
        "nonexistentuser12345", # Test case 3: Valid format, but non-existent user
        "invalid;user",         # Test case 4: Invalid format (command injection attempt)
        " a bad user"           # Test case 5: Invalid format (contains spaces)
    ]

    for i, username in enumerate(test_usernames, 1):
        print(f"Test Case {i}: Running command for username '{username}'")
        exit_status = execute_id_command(username)
        print(f"Exit Status: {exit_status}")
        print("----------------------------------------")

if __name__ == "__main__":
    main()