
import subprocess
import sys

def execute_command(username):
    try:
        command = f"cat /etc/passwd | grep {username}"
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        return f"Error executing command: {str(e)}"

def main():
    test_users = ["root", "daemon", "bin", "sys", "nobody"]
    
    if len(sys.argv) > 1:
        username = sys.argv[1]
        print(f"User information for: {username}")
        print(execute_command(username))
    else:
        print("Running test cases:")
        for user in test_users:
            print(f"=== User: {user} ===")
            print(execute_command(user))

if __name__ == "__main__":
    main()
