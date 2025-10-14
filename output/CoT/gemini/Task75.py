import os
import signal
import sys
import platform
import subprocess

def terminate_process(pid):
    """
    Terminates a process with the given PID.
    This function is cross-platform. It uses `os.kill` on POSIX systems
    and the `taskkill` command on Windows for robust termination.

    Args:
        pid (int): The process ID to terminate.
    
    Returns:
        bool: True if termination was successful, False otherwise.
    """
    if not isinstance(pid, int) or pid <= 0:
        print(f"Error: Invalid PID '{pid}'. PID must be a positive integer.")
        return False

    try:
        if platform.system() != "Windows":
            # On POSIX systems, SIGKILL provides a forceful termination.
            os.kill(pid, signal.SIGKILL)
            print(f"Successfully sent SIGKILL to PID: {pid}")
        else:
            # On Windows, os.kill is less reliable for forceful termination.
            # The 'taskkill' command is a more robust equivalent to SIGKILL.
            # We capture output to prevent it from printing to the console.
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                check=True,
                capture_output=True,
                text=True
            )
            print(f"Successfully terminated PID: {pid} using taskkill.")
        return True
    except ProcessLookupError:
        print(f"Error: No process found with PID: {pid}")
        return False
    except PermissionError:
        print(f"Error: Permission denied to terminate PID: {pid}. Try running with elevated privileges.")
        return False
    except subprocess.CalledProcessError as e:
        # This catches errors from taskkill, e.g., if the process doesn't exist.
        error_message = e.stderr.strip()
        print(f"Error terminating PID {pid} with taskkill: {error_message}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def main():
    """
    Main function to parse command-line arguments and call the termination function.
    """
    # --- Test Cases ---
    # To run the test cases, save the code as a Python file (e.g., terminate.py) and run from the command line.
    # You will need to find a valid PID on your system to test case 1.
    # - On Linux/macOS, you can run `sleep 100 &` to get a background process and its PID.
    # - On Windows, you can open Notepad and find its PID in Task Manager.
    #
    # 1. Kill a valid process (e.g., a process with PID 1234):
    #    python terminate.py 1234
    #
    # 2. Attempt to kill a non-existent process:
    #    python terminate.py 999999
    #
    # 3. Attempt to kill a privileged process (e.g., PID 1 on Linux):
    #    python terminate.py 1
    #    (This should fail with a permission error)
    #
    # 4. Provide non-numeric input:
    #    python terminate.py abc
    #
    # 5. Provide an invalid PID number:
    #    python terminate.py 0
    
    if len(sys.argv) != 2:
        script_name = os.path.basename(__file__)
        print(f"Usage: python {script_name} <PID>")
        sys.exit(1)

    pid_str = sys.argv[1]
    try:
        pid_to_kill = int(pid_str)
        terminate_process(pid_to_kill)
    except ValueError:
        print(f"Error: Invalid PID '{pid_str}'. Please provide a numeric value.")
        sys.exit(1)

if __name__ == "__main__":
    main()