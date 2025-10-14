import os
import signal
import sys
import subprocess
import time

def terminate_process(pid):
    """
    Terminates a process by its PID using a forceful signal (SIGKILL).

    Args:
        pid (int): The Process ID of the process to terminate.

    Returns:
        bool: True if the signal was sent successfully, False otherwise.
    """
    # Security: Validate PID. PIDs must be positive integers.
    # This prevents special values like 0 and -1 which signal process groups.
    if not isinstance(pid, int) or pid <= 0:
        print(f"Error: Invalid PID {pid}. PID must be a positive integer.", file=sys.stderr)
        return False

    # Security: Prevent the process from terminating itself.
    if pid == os.getpid():
        print("Error: Attempting to terminate the current process is not allowed.", file=sys.stderr)
        return False

    print(f"Attempting to terminate PID: {pid}")
    try:
        # Use SIGKILL for a forceful termination.
        # For a graceful shutdown, signal.SIGTERM could be used.
        os.kill(pid, signal.SIGKILL)
        print(f"Termination signal sent successfully to PID: {pid}")
        return True
    except ProcessLookupError:
        print(f"Error: Process with PID {pid} not found.", file=sys.stderr)
        return False
    except PermissionError:
        print(f"Error: Permission denied to terminate PID {pid}.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return False

def run_test_cases():
    """Runs a suite of test cases for the terminate_process function."""
    print("\n--- Running Test Suite ---")

    # Test Case 1: Terminate a valid child process.
    child_process = None
    try:
        print("\n--- Test Case 1: Valid PID ---")
        is_windows = sys.platform.startswith('win')
        command = ['timeout', '300'] if is_windows else ['sleep', '300']
        # On Windows, Popen with SIGKILL needs shell=True to terminate the actual child (timeout.exe)
        # However, for security, it's better to avoid shell=True. The default behavior is sufficient here.
        child_process = subprocess.Popen(command)
        child_pid = child_process.pid
        print(f"Started child process with PID: {child_pid}")
        time.sleep(1)
        
        terminate_process(child_pid)
        
        time.sleep(1)
        # poll() returns the exit code if terminated, None otherwise.
        if child_process.poll() is None:
            print("Child process is still alive (termination might have failed).")
            child_process.kill() # Final cleanup
        else:
            print(f"Child process terminated successfully.")

    except Exception as e:
        print(f"Failed to create or manage child process for testing: {e}", file=sys.stderr)
        if child_process:
            child_process.kill()

    # Test Case 2: Attempt to terminate a non-existent PID.
    print("\n--- Test Case 2: Non-existent PID ---")
    terminate_process(99999)

    # Test Case 3: Attempt to terminate PID 0 (rejected by validation).
    print("\n--- Test Case 3: Invalid PID (0) ---")
    terminate_process(0)

    # Test Case 4: Attempt to terminate PID -1 (rejected by validation).
    print("\n--- Test Case 4: Invalid PID (-1) ---")
    terminate_process(-1)

    # Test Case 5: Attempt to terminate the current process.
    print("\n--- Test Case 5: Self-termination ---")
    terminate_process(os.getpid())

    print("\n--- Test Suite Finished ---")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            pid_to_kill = int(sys.argv[1])
            terminate_process(pid_to_kill)
        except ValueError:
            print("Error: Invalid input. PID must be a numeric value.", file=sys.stderr)
            sys.exit(1)
    else:
        print("No PID provided. Running test cases...")
        run_test_cases()