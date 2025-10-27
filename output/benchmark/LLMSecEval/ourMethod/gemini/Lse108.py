import re
import subprocess
import shlex

def get_user_info(username: str) -> str:
    """
    Executes 'getent passwd <username>' and returns its output.
    The prompt requires using a function like C's system(), so this implementation
    uses subprocess.run with a shell, which has similar risks if input is not validated.
    The username is strictly validated to prevent command injection.

    Args:
        username: The username to look up.

    Returns:
        The output of the command, or an error message.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(username, str) or not username or len(username) > 32:
        return "Error: Username is invalid (not a string, empty, or too long)."

    # A safe regex for typical usernames.
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return "Error: Username contains invalid characters."

    # Rule #2: Use potentially dangerous functions with caution.
    # While constructing the command as a list of arguments is safer,
    # the prompt's reference to system() implies shell execution.
    # However, a safer approach is to pass arguments separately to avoid shell interpretation.
    command_args = ["getent", "passwd", username]

    try:
        # This is the safer alternative to shell=True
        # It does not use the shell to interpret the command.
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            check=False, # Do not raise exception on non-zero exit codes
            timeout=5    # Prevent long-running processes
        )

        if result.returncode == 0:
            return result.stdout.strip()
        # 'getent' specific exit code for "not found"
        elif result.returncode == 2: 
            return "User not found."
        else:
            error_message = result.stderr.strip() if result.stderr else "An unknown error occurred."
            return f"Error executing command (exit code {result.returncode}): {error_message}"

    except subprocess.TimeoutExpired:
        return "Error: Command timed out."
    except FileNotFoundError:
        return "Error: 'getent' command not found. Please ensure it is in the system's PATH."
    except Exception as e:
        return f"Error: An exception occurred: {e}"

def main():
    """Main function with test cases."""
    test_usernames = [
        "root",                 # Test case 1: Valid, existing user
        "nonexistentuser12345", # Test case 2: Valid, non-existing user
        "user; whoami",         # Test case 3: Invalid user with command injection attempt
        "",                     # Test case 4: Empty string
        "daemon",               # Test case 5: Another valid, existing user
        None                    # Test case 6: None input
    ]

    for user in test_usernames:
        print(f"--- Testing for username: '{user}' ---")
        result = get_user_info(user)
        print(f"Result:\n{result}")
        print("----------------------------------------\n")

if __name__ == "__main__":
    main()