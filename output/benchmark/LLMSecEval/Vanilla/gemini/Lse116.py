import os

def execute_command(command: str) -> int:
    """
    Executes a shell command using os.system.
    The os.system() function executes the command in a subshell.
    
    Args:
        command: The command string to execute.
        
    Returns:
        The exit status of the command.
    """
    # The return value is the exit status of the process.
    exit_code = os.system(command)
    return exit_code

def main():
    """
    Main function to run test cases.
    """
    test_commands = [
        "ls",
        "ls -l",
        "ls -a",
        "ls -al",
        "ls non_existent_directory"
    ]

    for i, cmd in enumerate(test_commands):
        # Using an f-string (Python's modern formatting) to create the output string.
        header = f"--- Test Case {i + 1}: Executing '{cmd}' ---"
        print(header)
        
        exit_code = execute_command(cmd)

        # On Unix, the return value is a 16-bit number. The high byte is the exit status.
        # We can get the actual exit code by right-shifting by 8.
        actual_exit_code = exit_code >> 8
        footer = f"--- Command exited with status: {actual_exit_code} ---\n"
        print(footer)


if __name__ == "__main__":
    main()