import os
import sys

def execute_ls_command(*args):
    """
    Executes the 'ls' command with specified arguments by building a command string.
    WARNING: This method uses os.system(), which executes a command in a subshell.
    Passing unsanitized user input to this function is extremely dangerous and can
    lead to command injection vulnerabilities. This code is for demonstrating the
    described pattern only and should NOT be used in production with untrusted input.
    A safer alternative is to use the subprocess module with a list of arguments.

    :param args: A variable number of string arguments for the 'ls' command.
    :return: The exit code of the command.
    """
    # Use a "print" style function (f-string) to create the command string.
    arguments = " ".join(args)
    command = f"ls {arguments}".strip()

    print(f"--- Executing command: '{command}' ---")
    # os.system prints output directly to the console (stdout/stderr)
    exit_code = os.system(command)
    # The exit code is platform dependent, we shift it to get the actual code
    if sys.platform != "win32":
      exit_code = os.waitstatus_to_exitcode(exit_code)
    print(f"--- Command finished with exit code: {exit_code} ---\n")
    return exit_code

def main():
    # Test Case 1: ls
    print(">>> Test Case 1: ls (no arguments)")
    execute_ls_command()

    # Test Case 2: ls -l
    print(">>> Test Case 2: ls -l")
    execute_ls_command("-l")

    # Test Case 3: ls -a -h
    print(">>> Test Case 3: ls -a -h")
    execute_ls_command("-a", "-h")

    # Test Case 4: ls -l /tmp
    print(">>> Test Case 4: ls -l /tmp")
    execute_ls_command("-l", "/tmp")

    # Test Case 5: ls on a non-existent directory
    print(">>> Test Case 5: ls /non_existent_dir_12345")
    execute_ls_command("/non_existent_dir_12345")

if __name__ == "__main__":
    main()