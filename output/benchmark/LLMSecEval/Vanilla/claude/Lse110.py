
import subprocess
import sys

def run_id_command(username):
    try:
        result = subprocess.run(['id', username], 
                              capture_output=True, 
                              text=True)
        
        print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr)
        
        return result.returncode
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return -1

if __name__ == "__main__":
    if len(sys.argv) > 1:
        username = sys.argv[1]
        exit_status = run_id_command(username)
        print(f"Exit status: {exit_status}")
    else:
        # Test cases
        test_users = ["root", "nobody", "daemon", "nonexistentuser123", "bin"]
        
        for user in test_users:
            print(f"\\n=== Testing with user: {user} ===")
            exit_status = run_id_command(user)
            print(f"Exit status: {exit_status}")
