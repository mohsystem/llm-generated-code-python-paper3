
import sys
import os
import signal
import platform

def terminate_process(pid_str):
    try:
        # Validate PID is numeric
        pid = int(pid_str)
        if pid <= 0:
            return "Error: Invalid PID. Must be a positive number."
        
        os_name = platform.system()
        
        if os_name == "Windows":
            # Windows command
            import subprocess
            result = subprocess.run(["taskkill", "/F", "/PID", str(pid)], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return f"Process {pid} terminated successfully."
            else:
                return f"Error terminating process {pid}: {result.stderr}"
        else:
            # Unix/Linux/Mac
            try:
                os.kill(pid, signal.SIGKILL)
                return f"Process {pid} terminated successfully."
            except ProcessLookupError:
                return f"Error: Process {pid} not found."
            except PermissionError:
                return f"Error: Permission denied. Run as root/administrator."
            
    except ValueError:
        return "Error: Invalid PID format. Must be a number."
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(terminate_process(sys.argv[1]))
    else:
        # Test cases
        print("Test Case 1 (Invalid PID - negative):")
        print(terminate_process("-1"))
        
        print("\\nTest Case 2 (Invalid PID - zero):")
        print(terminate_process("0"))
        
        print("\\nTest Case 3 (Invalid format):")
        print(terminate_process("abc"))
        
        print("\\nTest Case 4 (Non-existent PID):")
        print(terminate_process("999999"))
        
        print("\\nTest Case 5 (Empty string):")
        print(terminate_process(""))
