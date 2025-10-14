import subprocess
import platform
import re
import sys

def is_valid_input(input_str: str) -> bool:
    """
    Validates that the input contains only characters that are safe for a hostname or IP address.
    This is a critical defense-in-depth measure that uses an "allow-list" approach
    to prevent characters that could be used for command injection (e.g., ';', '|', '&', '$').

    Args:
        input_str: The string to validate.
    Returns:
        True if the input is valid, False otherwise.
    """
    if not isinstance(input_str, str) or not input_str.strip():
        return False
    # Allow alphanumeric characters, dots, and hyphens.
    return re.match(r'^[a-zA-Z0-9.-]+$', input_str) is not None

def secure_os_command(user_input: str):
    """
    Executes an OS command (ping) securely using user-provided input.
    It uses the subprocess module with a list of arguments (shell=False by default)
    to prevent command injection.

    Args:
        user_input: The destination (hostname or IP) to be pinged.
    """
    print(f"--- Executing command for input: '{user_input}' ---")

    if not is_valid_input(user_input):
        print("Invalid input format. Aborting command execution.")
        print("-------------------------------------------------")
        return

    try:
        # Determine the correct count argument for ping based on the OS to prevent flooding
        param = '-n' if platform.system().lower() == 'windows' else '-c'

        # The command and its arguments are passed as a list.
        # This prevents the shell from interpreting the user_input string.
        # `shell=False` is the default and is the secure option.
        command = ['ping', param, '4', user_input]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False  # Do not raise exception on non-zero exit; we will check it manually
        )

        print("STDOUT:")
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        print(f"\nExited with code: {result.returncode}")

    except FileNotFoundError:
        print(f"Error: The 'ping' command was not found on this system.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    finally:
        print("-------------------------------------------------")

def main():
    test_cases = [
        "127.0.0.1",              # Valid IP address
        "google.com",             # Valid hostname
        "invalid-hostname!",      # Invalid character, should be rejected by validation
        "127.0.0.1; ls",          # Classic command injection, should be rejected by validation
        "$(reboot)"               # Command substitution, should be rejected by validation
    ]

    for test_case in test_cases:
        secure_os_command(test_case)

if __name__ == "__main__":
    main()