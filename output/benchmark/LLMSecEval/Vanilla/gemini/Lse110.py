import subprocess

def run_id_command(username):
    """
    Runs the 'id <username>' command and returns its exit status.
    :param username: The username to look up.
    :return: The exit status of the 'id' command (0 for success, non-zero for failure).
    """
    if not username:
        # The 'id' command without arguments has a different meaning,
        # so we treat an empty username as an invalid input.
        return -1

    try:
        # Pass command and arguments as a list to avoid shell injection.
        # capture_output=True prevents the command's stdout/stderr from being printed.
        result = subprocess.run(['id', username], capture_output=True)
        return result.returncode
    except FileNotFoundError:
        # This happens if the 'id' command itself is not found
        return -1 # Or a different special value like 127

def main():
    """Main function with test cases."""
    test_cases = [
        "root",                   # Test case 1: Should exist on most systems (success)
        "daemon",                 # Test case 2: Should also exist on most systems (success)
        "nonexistentuser12345",   # Test case 3: Should not exist (failure)
        "another_fake_user_xyz",  # Test case 4: Should not exist (failure)
        ""                        # Test case 5: Invalid input (failure)
    ]

    print("--- Running Python Test Cases ---")
    for user in test_cases:
        exit_status = run_id_command(user)
        user_display = user if user else "<empty>"
        print(f"Command 'id {user_display}' exited with status: {exit_status}")

if __name__ == "__main__":
    main()