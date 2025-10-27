
import subprocess
import sys

def getent_passwd(username):
    if not username:
        return "Error: Username cannot be empty"
    
    try:
        # Execute the getent passwd command
        command = f"getent passwd {username}"
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"Error: User '{username}' not found or command failed"
            
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def main():
    # Test cases
    test_users = ["root", "nobody", "daemon", "bin", "sys"]
    
    print("Testing getent passwd command:\\n")
    for user in test_users:
        print(f"User: {user}")
        print(getent_passwd(user))
        print("---")

if __name__ == "__main__":
    main()
