import os
import signal
import sys
from typing import NoReturn

def terminate_process(pid: int) -> bool:
    """
    Terminates a process by its Process ID (PID).

    Args:
        pid: The integer ID of the process to terminate.

    Returns:
        True if the termination signal was sent successfully, False otherwise.
    """
    if not isinstance(pid, int) or pid <= 0:
        print("Error: PID must be a positive integer.", file=sys.stderr)
        return False

    try:
        # On POSIX, sends SIGTERM.
        # On Windows, os.kill calls TerminateProcess.
        print(f"Attempting to terminate process with PID: {pid}")
        os.kill(pid, signal.SIGTERM)
        return True
    except ProcessLookupError:
        print(f"Error: Process with PID {pid} not found.", file=sys.stderr)
        return False
    except PermissionError:
        print(f"Error: Permission denied to terminate process with PID {pid}.", file=sys.stderr)
        return False
    except OSError as e:
        print(f"An OS error occurred while terminating PID {pid}: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False

def test_terminate(pid: int) -> None:
    """Helper function for running test cases."""
    print(f"\n--- Testing with PID: {pid} ---")
    if terminate_process(pid):
        print("Result: Termination signal sent successfully.")
    else:
        print("Result: Failed to send termination signal.")

def main() -> NoReturn:
    """
    Main function to parse command-line arguments and run the program.
    """
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <PID>")
        print("\n--- Running Built-in Test Cases ---")
        # Note: These test cases use placeholder PIDs.
        # To test effectively, start a process (e.g., 'sleep 300' in bash or 'timeout 300' in cmd)
        # and replace a placeholder with its actual PID.

        # Test 1: PID 1 (init/systemd/launchd), will likely fail due to permissions.
        test_terminate(1)
        
        # Test 2: A PID that is highly unlikely to exist.
        test_terminate(999999)

        # Test 3: An invalid PID (zero).
        test_terminate(0)

        # Test 4: An invalid PID (negative).
        test_terminate(-10)

        # Test 5: A placeholder for a real PID you can test with.
        test_terminate(12345)
        print("\n--- Test Cases Finished ---")
        sys.exit(1)

    pid_str = sys.argv[1]
    try:
        pid = int(pid_str)
        if terminate_process(pid):
            print(f"Termination signal was sent to process with PID: {pid}")
            sys.exit(0)
        else:
            print(f"Failed to terminate process with PID: {pid}")
            sys.exit(1)
    except ValueError:
        print(f"Error: Invalid PID '{pid_str}'. It must be an integer.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()