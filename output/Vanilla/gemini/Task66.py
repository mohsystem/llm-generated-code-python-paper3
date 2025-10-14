import subprocess

def execute_command(command: str) -> str:
    """
    Executes a shell command, validates its format, and returns the result.

    :param command: The shell command to execute.
    :return: A string containing the standard output, standard error, and exit code.
    """
    # 1. Validation: Check for non-string or empty/whitespace command
    if not isinstance(command, str) or not command.strip():
        return "Validation Error: Command cannot be null or empty."

    try:
        # 2. Execute command using the shell.
        # Note: shell=True can be a security hazard if the command is from an untrusted source.
        # It's used here to properly handle shell features like pipes.
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False  # Do not raise exception on non-zero exit codes
        )

        # 3. Combine stdout and stderr into a single result string
        output = ""
        if result.stdout:
            # rstrip to remove the trailing newline that subprocess might add
            output += result.stdout.rstrip('\n') + '\n'
        if result.stderr:
            output += f"ERROR: {result.stderr.rstrip(r'\\n')}\n"

        output += f"Exited with code: {result.returncode}"
        return output

    except Exception as e:
        return f"Execution Error: {e}"

if __name__ == "__main__":
    test_commands = [
        "echo 'Hello from Bash!'",            # Test Case 1: Simple echo
        "ls -l",                              # Test Case 2: List files
        "ls non_existent_directory",          # Test Case 3: Command with an error
        "echo 'one\\ntwo\\nthree' | grep 'two'", # Test Case 4: Command with a pipe
        "invalidcommand_xyz_123"              # Test Case 5: Invalid command
    ]

    for i, cmd in enumerate(test_commands, 1):
        print(f"--- Executing Test Case {i}: `{cmd}` ---")
        result = execute_command(cmd)
        print(f"Result:\n{result}")
        print(f"--- End Test Case {i} ---\n")