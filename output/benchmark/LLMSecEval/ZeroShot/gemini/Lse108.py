import re
import subprocess

def execute_getent(username: str) -> str:
    """
    Executes the 'getent passwd <username>' command securely.

    It validates the username against a strict regex and uses the subprocess module
    with a list of arguments to prevent shell command injection.

    Args:
        username: The username to look up.

    Returns:
        The output of the command, or an error message if the username is invalid
        or an error occurs during execution.
    """
    # Stricter regex for Linux usernames to prevent command injection.
    # It allows only a safe subset of characters.
    username_pattern = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
    if not isinstance(username, str) or not username_pattern.match(username):
        return "Error: Invalid username format.\n"

    try:
        # Using a list of arguments for the command is crucial for security,
        # as it prevents the shell from interpreting the username argument.
        command = ["getent", "passwd", username]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False  # Do not raise an exception on non-zero exit status.
        )
        
        # 'getent' returns a specific exit code (2) if the user is not found.
        if result.returncode == 0:
            return result.stdout
        elif result.returncode == 2:
            return "User not found.\n"
        else:
            # For other errors, return stderr if available for better diagnostics.
            error_message = result.stderr.strip() if result.stderr else "An unknown error occurred."
            return f"Error executing command (exit code {result.returncode}): {error_message}\n"

    except FileNotFoundError:
        return "Error: 'getent' command not found. Please ensure it is in your PATH.\n"
    except Exception as e:
        return f"An unexpected error occurred: {e}\n"

def main():
    """ Main function with test cases """
    test_usernames = [
        "root",                          # Test Case 1: Valid and existing user
        "nobody",                        # Test Case 2: Another valid user
        "thisuserdoesnotexist123",       # Test Case 3: Valid format, but likely non-existent
        "user;whoami",                   # Test Case 4: Command injection attempt (should be rejected)
        "us$er"                          # Test Case 5: Invalid character (should be rejected)
    ]

    for user in test_usernames:
        print(f"--- Testing with username: '{user}' ---")
        output = execute_getent(user)
        print("Output:")
        print(output, end="")
        print("----------------------------------------\n")

if __name__ == "__main__":
    main()