
import subprocess
import re

def execute_getent_passwd(username):
    """\n    Executes getent passwd command for the given username\n    Returns the user information as a string\n    """
    # Input validation
    if not username or not isinstance(username, str):
        return "Error: Username cannot be None or empty"
    
    # Sanitize username - only allow alphanumeric, underscore, and hyphen
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return "Error: Invalid username format"
    
    try:
        # Use subprocess with list arguments for safer execution
        result = subprocess.run(
            ['getent', 'passwd', username],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"Error: User '{username}' not found or command failed"
            
    except subprocess.TimeoutExpired:
        return "Error: Command execution timed out"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    # Test cases
    test_users = ["root", "nobody", "daemon", "testuser", "admin"]
    
    print("Testing getent passwd command:")
    print("================================\\n")
    
    for username in test_users:
        print(f"User: {username}")
        result = execute_getent_passwd(username)
        print(f"Result: {result}")
        print("--------------------------------\\n")

if __name__ == "__main__":
    main()
