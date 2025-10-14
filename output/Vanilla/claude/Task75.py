
import sys
import os
import platform
import subprocess

def terminate_process(pid):
    try:
        system = platform.system().lower()
        
        if system == "windows":
            result = subprocess.run(["taskkill", "/F", "/PID", str(pid)], 
                                  capture_output=True, text=True)
        else:
            result = subprocess.run(["kill", "-9", str(pid)], 
                                  capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Process {pid} terminated successfully.")
        else:
            print(f"Failed to terminate process {pid}.")
            if result.stderr:
                print(f"Error: {result.stderr.strip()}")
    except Exception as e:
        print(f"Error terminating process: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            pid = int(sys.argv[1])
            terminate_process(pid)
        except ValueError:
            print("Invalid PID format. Please provide a valid integer.")
    else:
        print("Running test cases...")
        print("\\nNote: These are demonstration test cases.")
        print("Please provide actual PIDs to terminate real processes.")
        
        print("\\nTest Case 1: PID 99999 (likely non-existent)")
        terminate_process(99999)
        
        print("\\nTest Case 2: PID 88888 (likely non-existent)")
        terminate_process(88888)
        
        print("\\nTest Case 3: PID 77777 (likely non-existent)")
        terminate_process(77777)
        
        print("\\nTest Case 4: PID 66666 (likely non-existent)")
        terminate_process(66666)
        
        print("\\nTest Case 5: PID 55555 (likely non-existent)")
        terminate_process(55555)
