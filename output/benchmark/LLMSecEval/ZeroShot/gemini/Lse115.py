import subprocess
import shlex

# Note: The prompt describes a pattern where a single formatted string is executed as a command.
# This is a classic command injection vulnerability (e.g., using os.system or shell=True).
# A secure implementation, as provided below, avoids this by never executing a command through a shell.
# Instead, the command ("ls") and its arguments are passed as a list of strings to the
# subprocess module. This ensures that arguments, even if they contain shell metacharacters
# like ';' or '|', are treated as literal strings and not as separate commands to be executed.

def format_argument(format_string, *args):
    """
    Creates a formatted string for use as a command argument.
    This function corresponds to the "print function" described in the prompt,
    but is used securely to format individual arguments, not the entire command string.
    
    :param format_string: A format string.
    :param args: Arguments for the format string.
    :return: A formatted string.
    """
    return format_string.format(*args)

def execute_ls(*args):
    """
    Executes the 'ls' command with the given arguments in a secure way.
    
    :param args: A variable number of string arguments for the 'ls' command.
    :return: The combined standard output and standard error of the command.
    """
    try:
        # The command and its arguments are passed as a list, which prevents shell injection.
        command = ["ls"] + list(args)
        
        # `shell=False` is the default and is the secure way to run commands.
        # `check=False` prevents an exception on non-zero exit codes so we can capture the error.
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        output = result.stdout + result.stderr
        output += f"---\nExit Code: {result.returncode}\n"
        return output
    except FileNotFoundError:
        return "Error: 'ls' command not found.\n"
    except Exception as e:
        return f"An error occurred: {e}\n"

if __name__ == "__main__":
    print("--- Test Case 1: ls -l ---")
    print(execute_ls("-l"))

    print("--- Test Case 2: ls -a / ---")
    print(execute_ls("-a", "/"))

    print("--- Test Case 3: ls /nonexistent_dir ---")
    print(execute_ls("/nonexistent_dir"))
    
    # Using the format_argument function to build an argument
    formatted_arg = format_argument("test_file_{}.txt", 123)
    print(f"--- Test Case 4: ls {formatted_arg} ---")
    print(execute_ls(formatted_arg))

    # Security Test Case: Attempting command injection.
    # The secure implementation will pass "; id" as a single argument to 'ls',
    # which will result in an error from 'ls', rather than executing the 'id' command.
    print("--- Test Case 5 (Security): ls '; id' ---")
    print(execute_ls("; id"))