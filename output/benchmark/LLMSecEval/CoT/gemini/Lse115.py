import subprocess

def custom_print(format_string, *args):
    """
    Formats a string using placeholders.
    """
    return format_string.format(*args)

def execute_command(command):
    """
    Executes a command line utility.
    WARNING: Executing commands from strings using shell=True is inherently
    dangerous if any part of the string comes from an untrusted source, as it can
    lead to command injection vulnerabilities. This is for demonstration purposes only.
    """
    try:
        # Using shell=True to execute the command string. This is the security risk.
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False # Do not raise exception for non-zero exit codes
        )
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += f"ERROR: {result.stderr}"
        output += f"Exited with error code: {result.returncode}"
        return output
    except Exception as e:
        return f"Exception occurred: {e}"

def main():
    """Main function with test cases."""
    print("--- Test Case 1: ls -l ---")
    command1 = custom_print("{} {}", "ls", "-l")
    print(f"Executing: {command1}")
    print(execute_command(command1))
    print("--------------------------\n")
    
    print("--- Test Case 2: ls -a /tmp ---")
    command2 = custom_print("{} {} {}", "ls", "-a", "/tmp")
    print(f"Executing: {command2}")
    print(execute_command(command2))
    print("--------------------------\n")

    print("--- Test Case 3: ls -lh /var ---")
    # Note: /var may not be readable by the current user
    command3 = custom_print("{} {} {}", "ls", "-lh", "/var")
    print(f"Executing: {command3}")
    print(execute_command(command3))
    print("--------------------------\n")
    
    print("--- Test Case 4: ls / ---")
    command4 = custom_print("{} {}", "ls", "/")
    print(f"Executing: {command4}")
    print(execute_command(command4))
    print("--------------------------\n")
    
    print("--- Test Case 5: ls --version ---")
    command5 = custom_print("{} {}", "ls", "--version")
    print(f"Executing: {command5}")
    print(execute_command(command5))
    print("--------------------------\n")

if __name__ == "__main__":
    main()