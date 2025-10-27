import subprocess
import re
import shlex

def get_user_info(username: str) -> str:
    """
    Executes the command 'getent passwd <username>' and returns its output.

    Args:
        username: The username to look up.

    Returns:
        The output of the command, or an error message if the input is invalid.
    """
    # A regex for typical Linux usernames.
    # It must not contain shell metacharacters to prevent command injection.
    # Usernames are typically 1-32 chars, containing a-z, 0-9, _, -.
    if not username or not re.match(r'^[a-zA-Z0-9_-]{1,32}$', username):
        return "Error: Invalid username format."

    # Using a list of arguments with subprocess.run is the secure way to call
    # external commands. It avoids using the shell and prevents injection.
    command = ["getent", "passwd", username]
    
    try:
        # We capture both stdout and stderr. text=True decodes them as strings.
        # check=False prevents raising an exception on non-zero exit codes.
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        # Combine stdout and stderr for the full picture.
        # getent typically writes nothing to stdout if user not found.
        output = result.stdout + result.stderr
        return output if output else "No output received (user may not exist)."

    except FileNotFoundError:
        return "Error: 'getent' command not found. This program is intended for Unix-like systems."
    except Exception as e:
        return f"An unexpected error occurred: {e}"


def main():
    """Main function with test cases."""
    test_usernames = [
        "root",                 # Test Case 1: A valid, existing user
        "nonexistentuser12345", # Test Case 2: A valid but likely non-existing user
        "user name",            # Test Case 3: Invalid format (space)
        "root;whoami",          # Test Case 4: Command injection attempt
        ""                      # Test Case 5: Empty username
    ]

    for user in test_usernames:
        print(f"---- Testing for username: '{user}' ----")
        result = get_user_info(user)
        print(result.strip())
        print("----------------------------------------\n")

if __name__ == "__main__":
    main()