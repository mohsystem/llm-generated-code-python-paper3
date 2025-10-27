
import subprocess
import re
import sys

# Username validation pattern: alphanumeric, dash, underscore only
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

def get_user_info(username):
    """\n    Securely execute 'id' command for given username.\n    Returns exit status of the command.\n    """
    # Input validation to prevent command injection
    if not username or not isinstance(username, str):
        print("Error: Username cannot be empty", file=sys.stderr)
        return -1
    
    if not USERNAME_PATTERN.match(username):
        print("Error: Invalid username format", file=sys.stderr)
        return -1
    
    try:
        # Use list format to prevent shell injection
        result = subprocess.run(
            ['id', username],
            capture_output=True,
            timeout=5
        )
        return result.returncode
        
    except subprocess.TimeoutExpired:
        print("Error: Command timeout", file=sys.stderr)
        return -1
    except Exception as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        return -1

def main():
    # Test cases
    test_users = ["root", "nobody", "invaliduser123", "test-user", "invalid;user"]
    
    if len(sys.argv) > 1:
        # Use command line argument
        exit_status = get_user_info(sys.argv[1])
        print(f"Exit status: {exit_status}")
    else:
        # Run test cases
        print("Running test cases:")
        for user in test_users:
            print(f"\\nTesting user: {user}")
            exit_status = get_user_info(user)
            print(f"Exit status: {exit_status}")

if __name__ == "__main__":
    main()
