import os
import sys

def execute_ls_command(args_str: str) -> int:
    """
    Executes the 'ls' command with the given arguments.
    This function uses an f-string (a "print"/formatting function) to create the command string
    and the os.system() function to execute it.

    :param args_str: A string containing the arguments for the 'ls' command.
    :return: The exit code of the command.
    """
    # An f-string is used to create the string that is passed to system.
    # It acts as a formatting/print function.
    command = f"ls {args_str}"
    print(f"Executing: {command}")
    
    # The os.system function takes a string as an argument and executes it
    # as a command line utility.
    exit_code = os.system(command)
    return exit_code

def main():
    """Main function with test cases."""
    test_cases = [
        "-l",
        "-a .",
        "/dev/null",
        "/tmp",
        "-lh /"
    ]
    
    for i, case in enumerate(test_cases, 1):
        print(f"--- Test Case {i} ---")
        print(f"Arguments: '{case}'")
        # os.system() returns a 16-bit number; the high byte is the exit status.
        # On POSIX systems, we can right-shift by 8 to get the actual exit code.
        raw_status = execute_ls_command(case)
        if sys.platform != "win32":
            exit_code = os.waitstatus_to_exitcode(raw_status)
        else:
            exit_code = raw_status # On Windows, it's just the return code
        print(f"\nExit Code: {exit_code}")
        print(f"--- End Test Case {i} ---\n")

if __name__ == "__main__":
    main()