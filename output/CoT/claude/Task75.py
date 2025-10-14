
import os
import sys
import signal
import re

def terminate_process(pid_str):
    """\n    Terminates a process by PID with security validations\n    Args:\n        pid_str: Process ID as string\n    Returns:\n        bool: True if successful, False otherwise\n    """
    # Input validation - prevent injection attacks
    if not pid_str or not pid_str.strip():
        print("Error: PID cannot be null or empty", file=sys.stderr)
        return False
    
    # Validate PID is numeric only (prevent command injection)
    if not re.match(r'^[0-9]+$', pid_str.strip()):
        print("Error: PID must contain only digits", file=sys.stderr)
        return False
    
    try:
        pid = int(pid_str.strip())
        
        # Validate PID is positive
        if pid <= 0:
            print("Error: PID must be positive", file=sys.stderr)
            return False
        
        # Security: prevent terminating system critical PIDs (1-1000)
        if pid <= 1000:
            print("Warning: Cannot terminate system process (PID <= 1000)", file=sys.stderr)
            return False
        
        # Check if process exists before attempting termination
        try:
            os.kill(pid, 0)  # Signal 0 checks if process exists without killing
        except ProcessLookupError:
            print(f"Error: Process {pid} does not exist", file=sys.stderr)
            return False
        except PermissionError:
            print(f"Error: Insufficient permissions to access process {pid}", file=sys.stderr)
            return False
        
        # Attempt to terminate the process
        try:
            os.kill(pid, signal.SIGTERM)  # Try graceful termination first
            print(f"Process {pid} terminated successfully")
            return True
        except PermissionError:
            print(f"Error: Insufficient permissions to terminate process {pid}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Error: Failed to terminate process {pid}", file=sys.stderr)
            return False
            
    except ValueError:
        print("Error: Invalid PID format", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: Unexpected error - {type(e).__name__}", file=sys.stderr)
        return False

def main():
    """Main function with test cases"""
    print("=== Process Termination Test Cases ===\\n")
    
    # Test Case 1: Valid PID format
    print("Test 1: Valid PID (12345)")
    terminate_process("12345")
    print()
    
    # Test Case 2: Invalid PID (negative)
    print("Test 2: Negative PID (-100)")
    terminate_process("-100")
    print()
    
    # Test Case 3: Invalid PID (non-numeric)
    print("Test 3: Non-numeric PID (abc123)")
    terminate_process("abc123")
    print()
    
    # Test Case 4: System process protection
    print("Test 4: System process (PID 1)")
    terminate_process("1")
    print()
    
    # Test Case 5: Empty/null input
    print("Test 5: Empty PID")
    terminate_process("")
    print()
    
    # Command line argument handling
    if len(sys.argv) > 1:
        print("=== Command Line Execution ===")
        for pid in sys.argv[1:]:
            print(f"Attempting to terminate PID: {pid}")
            terminate_process(pid)

if __name__ == "__main__":
    main()
