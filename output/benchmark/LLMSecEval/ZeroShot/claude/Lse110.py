
import subprocess
import sys
import re

def execute_id_command(username):
    if not username or not username.strip():
        return -1
    
    # Sanitize username to prevent command injection
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        print("Invalid username format", file=sys.stderr)
        return -1
    
    try:
        result = subprocess.run(
            ['id', username],
            capture_output=True,
            text=True
        )
        
        # Print output
        if result.stdout:
            print(result.stdout.strip())
        
        # Print errors
        if result.stderr:
            print(result.stderr.strip(), file=sys.stderr)
        
        return result.returncode
        
    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        return -1

def main():
    # Test cases
    test_cases = ["root", "nobody", "daemon", "invaliduser123", "admin"]
    
    if len(sys.argv) > 1:
        # Use command line argument if provided
        exit_status = execute_id_command(sys.argv[1])
        print(f"Exit status: {exit_status}")
    else:
        # Run test cases
        print("Running test cases:\\n")
        for username in test_cases:
            print(f"Testing username: {username}")
            exit_status = execute_id_command(username)
            print(f"Exit status: {exit_status}")
            print("---")

if __name__ == "__main__":
    main()
