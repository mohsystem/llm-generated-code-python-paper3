
import re
import sys
import subprocess
from typing import Optional

PID_PATTERN = re.compile(r'^[1-9][0-9]{0,9}$')
MAX_PID = 2147483647

def terminate_process(pid_string: Optional[str]) -> str:
    """\n    Terminates a process by its PID with input validation.\n    \n    Args:\n        pid_string: String representation of the process ID\n        \n    Returns:\n        Status message indicating success or error\n    """
    # Validate input is not None or empty
    if pid_string is None or not pid_string.strip():
        return "Error: PID cannot be None or empty"
    
    # Sanitize input - remove whitespace
    pid_string = pid_string.strip()
    
    # Validate PID format (positive integer only)
    if not PID_PATTERN.match(pid_string):
        return "Error: Invalid PID format. Must be a positive integer"
    
    # Parse and validate range
    try:
        pid = int(pid_string)
        if pid <= 0 or pid > MAX_PID:
            return f"Error: PID out of valid range (1-{MAX_PID})"
    except ValueError:
        return "Error: Invalid PID number"
    
    # Attempt to terminate process
    try:
        if sys.platform.startswith('win'):
            result = subprocess.run(
                ['taskkill', '/F', '/PID', str(pid)],
                capture_output=True,
                timeout=5
            )
        else:
            result = subprocess.run(
                ['kill', '-9', str(pid)],
                capture_output=True,
                timeout=5
            )
        
        if result.returncode == 0:
            return f"Success: Process {pid} terminated"
        else:
            return f"Error: Failed to terminate process {pid}"
    except subprocess.TimeoutExpired:
        return "Error: Operation timed out"
    except Exception as e:
        return f"Error: Exception occurred - {type(e).__name__}"

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <PID>", file=sys.stderr)
        sys.exit(1)
    
    result = terminate_process(sys.argv[1])
    print(result)
    
    # Test cases
    print("\\nTest Cases:")
    print(f"Test 1 (valid format): {terminate_process('12345')}")
    print(f"Test 2 (None): {terminate_process(None)}")
    print(f"Test 3 (empty): {terminate_process('')}")
    print(f"Test 4 (negative): {terminate_process('-100')}")
    print(f"Test 5 (invalid chars): {terminate_process('12a45')}")

if __name__ == "__main__":
    main()
