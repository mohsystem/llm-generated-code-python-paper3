import os
import sys
import signal
import platform
import subprocess
import time

def terminate_process(pid: int) -> bool:
    """
    Terminates a process by its Process ID (PID).
    :param pid: The integer PID of the process to terminate.
    :return: True if the process was terminated successfully, False otherwise.
    """
    if not isinstance(pid, int) or pid <= 0:
        return False
        
    system = platform.system()
    try:
        if system == "Windows":
            # On Windows, 'taskkill' is a robust way to terminate a process.
            # We redirect output to DEVNULL to keep the console clean.
            res = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                check=False, # Don't raise exception on non-zero exit
                capture_output=True
            )
            return res.returncode == 0
        else: # Linux, macOS, and other POSIX systems
            # os.kill sends a signal to the process. SIGKILL is a forceful termination.
            os.kill(pid, signal.SIGKILL)
            return True
    except (ProcessLookupError, PermissionError):
        # ProcessLookupError: The PID does not exist.
        # PermissionError: Not enough rights to terminate the process.
        return False
    except Exception:
        # Catch any other unexpected errors.
        return False

def start_dummy_process():
    """Starts a dummy background process for testing purposes."""
    try:
        command = ["timeout", "60"] if platform.system() == "Windows" else ["sleep", "60"]
        # Start the process in the background, hiding its output
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return process
    except FileNotFoundError:
        print("Error: 'sleep' or 'timeout' command not found.", file=sys.stderr)
        return None

def main():
    if len(sys.argv) > 1:
        try:
            pid_to_kill = int(sys.argv[1])
            print(f"Attempting to terminate process with PID: {pid_to_kill}")
            if terminate_process(pid_to_kill):
                print(f"Termination command for process {pid_to_kill} sent successfully.")
            else:
                print(f"Failed to terminate process {pid_to_kill}. It might not exist or you may lack permissions.")
        except ValueError:
            print("Invalid PID provided. Please enter a numeric PID.", file=sys.stderr)
    else:
        print("No PID provided. Running built-in test cases...")
        
        # Test Case 1: Terminate a valid process
        print("\n--- Test Case 1: Terminate a valid process ---")
        p1 = start_dummy_process()
        if p1:
            pid1 = p1.pid
            print(f"Started dummy process with PID: {pid1}")
            time.sleep(0.1) # Ensure process is fully started
            result1 = terminate_process(pid1)
            print(f"Termination result: {'SUCCESS' if result1 else 'FAILURE'}")
            time.sleep(0.1) # Give OS time to update process status
            # p1.poll() returns None if running, or the exit code if terminated.
            print(f"Is process still alive? {p1.poll() is None}")

            # Test Case 5: Attempt to terminate an already terminated process
            print("\n--- Test Case 5: Re-terminate the same process ---")
            print(f"Attempting to terminate PID {pid1} again.")
            result5 = terminate_process(pid1)
            print(f"Second termination result: {'SUCCESS' if result5 else 'FAILURE (Expected)'}")
        else:
            print("Skipping Test 1 & 5 as dummy process could not be started.")

        # Test Case 2: Terminate another valid process
        print("\n--- Test Case 2: Terminate another valid process ---")
        p2 = start_dummy_process()
        if p2:
            pid2 = p2.pid
            print(f"Started second dummy process with PID: {pid2}")
            time.sleep(0.1)
            result2 = terminate_process(pid2)
            print(f"Termination result: {'SUCCESS' if result2 else 'FAILURE'}")
        else:
            print("Skipping Test 2 as dummy process could not be started.")

        # Test Case 3: Terminate a non-existent process
        print("\n--- Test Case 3: Terminate a non-existent process ---")
        non_existent_pid = 99999
        print(f"Attempting to terminate non-existent PID: {non_existent_pid}")
        result3 = terminate_process(non_existent_pid)
        print(f"Termination result: {'SUCCESS' if result3 else 'FAILURE (Expected)'}")
        
        # Test Case 4: Terminate an invalid PID (<=0)
        print("\n--- Test Case 4: Terminate an invalid PID (e.g., 0) ---")
        invalid_pid = 0
        print(f"Attempting to terminate invalid PID: {invalid_pid}")
        result4 = terminate_process(invalid_pid)
        print(f"Termination result: {'SUCCESS' if result4 else 'FAILURE (Expected)'}")


if __name__ == "__main__":
    main()