
import subprocess
import re
import sys

# Whitelist pattern: alphanumeric, underscore, hyphen only
# This prevents command injection through special shell characters
SAFE_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
MAX_USERNAME_LENGTH = 32


def execute_id_command(username: str) -> int:
    """\n    Executes the id command for a given username.\n    Returns the exit status of the command.\n    \n    Args:\n        username: The username to query (must match safe pattern)\n    \n    Returns:\n        Exit status: 0 for success, non-zero for failure, -1 for invalid input\n    """
    # Input validation: check for None or empty
    if username is None or username == "":
        print("Error: Username cannot be None or empty", file=sys.stderr)
        return -1

    # Input validation: check type
    if not isinstance(username, str):
        print("Error: Username must be a string", file=sys.stderr)
        return -1

    # Input validation: check length to prevent buffer issues
    if len(username) > MAX_USERNAME_LENGTH:
        print("Error: Username exceeds maximum length", file=sys.stderr)
        return -1

    # Input validation: sanitize username to prevent command injection
    # Only allow alphanumeric characters, underscore, and hyphen
    if not SAFE_USERNAME_PATTERN.match(username):
        print("Error: Username contains invalid characters", file=sys.stderr)
        return -1

    try:
        # Use subprocess with argument list instead of shell execution
        # This prevents command injection by treating username as a single argument
        # shell=False is critical - never use shell=True with user input
        result = subprocess.run(
            ["id", username],
            shell=False,  # Explicitly disable shell to prevent injection
            capture_output=True,
            text=True,
            timeout=5  # Prevent indefinite hanging
        )

        # Display output (stdout and stderr combined)
        if result.stdout:
            print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr)

        return result.returncode

    except subprocess.TimeoutExpired:
        print("Error: Command execution timed out", file=sys.stderr)
        return -1
    except FileNotFoundError:
        # Generic error message to avoid information leakage
        print("Error: Command not found", file=sys.stderr)
        return -1
    except Exception:
        # Generic error message to avoid information leakage
        print("Error: Failed to execute command", file=sys.stderr)
        return -1


def main():
    """Main function with test cases"""
    # Test cases
    test_users = ["root", "nobody", "testuser123", "user-name", "invalid@user"]

    if len(sys.argv) > 1:
        # Use command line argument if provided
        username = sys.argv[1]
        exit_status = execute_id_command(username)
        print(f"Exit status: {exit_status}")
    else:
        # Run test cases
        print("Running test cases:")
        for user in test_users:
            print(f"\\n--- Testing with username: {user} ---")
            exit_status = execute_id_command(user)
            print(f"Exit status: {exit_status}")


if __name__ == "__main__":
    main()
