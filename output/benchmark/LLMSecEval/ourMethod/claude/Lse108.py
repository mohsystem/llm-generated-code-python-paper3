
import subprocess
import re
import shlex

# Pattern to validate username: alphanumeric, underscore, hyphen, and dot only
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')

def get_user_info(username):
    """\n    Executes getent passwd command for a given username.\n    Uses secure command execution to prevent command injection.\n    Validates username format before execution.\n    \n    Args:\n        username: The username to query\n        \n    Returns:\n        The output from getent passwd command, or error message\n    """
    # Security: Validate username format to prevent command injection
    if not username:
        return "Error: Username cannot be None or empty"
    
    # Security: Reject usernames with invalid characters to prevent injection
    if not USERNAME_PATTERN.match(username):
        return "Error: Invalid username format"
    
    try:
        # Security: Use subprocess with list arguments to prevent shell injection
        # shell=False ensures no shell interpretation occurs
        result = subprocess.run(
            ['getent', 'passwd', username],
            capture_output=True,
            text=True,
            timeout=5,  # Security: Timeout to prevent hanging
            check=False,
            shell=False  # Security: Critical - prevents shell injection
        )
        
        # Check exit code
        if result.returncode != 0:
            if result.returncode == 2:
                return f"Error: User '{username}' not found"
            return f"Error: Command failed with exit code {result.returncode}"
        
        # Security: Limit output size to prevent DoS
        MAX_OUTPUT_SIZE = 4096
        output = result.stdout[:MAX_OUTPUT_SIZE]
        
        return output
        
    except subprocess.TimeoutExpired:
        return "Error: Command execution timeout"
    except FileNotFoundError:
        return "Error: getent command not found"
    except Exception as e:
        # Security: Don't leak internal details\n
        return "Error: Operation failed"

def main():
    # Test case 1: Valid username
    print("Test 1 - Valid user 'root':")
    print(get_user_info("root"))

    # Test case 2: Valid username
    print("\nTest 2 - Valid user 'daemon':")
    print(get_user_info("daemon"))

    # Test case 3: Non-existent user
    print("\nTest 3 - Non-existent user:")
    print(get_user_info("nonexistentuser12345"))

    # Test case 4: Invalid username with shell metacharacter (injection attempt)
    print("\nTest 4 - Invalid username (injection attempt):")
    print(get_user_info("root; rm -rf /"))

    # Test case 5: Empty username
    print("\nTest 5 - Empty username:")
    print(get_user_info(""))

if __name__ == "__main__":
    main()
