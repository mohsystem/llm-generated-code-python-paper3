import subprocess
import sys

def get_user_info(username):
    """
    Executes 'cat /etc/passwd | grep <username>' using a shell and returns the output.
    """
    # Use a more specific grep to avoid partial matches and anchor to the start of the line.
    command = f"cat /etc/passwd | grep '^{username}:'"
    
    try:
        # shell=True is required to interpret the pipe '|'.
        # check=False prevents raising an exception if grep finds no matches (returns exit code 1).
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        if result.returncode == 0:
            # Command was successful and found a match.
            return result.stdout
        elif result.returncode == 1:
            # grep returns 1 if no lines were selected (user not found).
            return f"User '{username}' not found.\n"
        else:
            # Another error occurred.
            return f"An error occurred:\n{result.stderr}"
            
    except Exception as e:
        return f"Failed to execute command: {e}\n"

def main():
    # sys.argv[0] is the script name, so we check for more than 1 argument.
    if len(sys.argv) > 1:
        username = sys.argv[1]
        # Use end='' because the returned string already has a newline.
        print(get_user_info(username), end='')
    else:
        print("No command line argument provided. Running built-in test cases:")
        print("===============================================================")
        test_cases = ["root", "daemon", "bin", "sys", "nonexistentuser123"]
        for user in test_cases:
            print(f"\n--- Testing for user: '{user}' ---")
            print(get_user_info(user), end='')

if __name__ == "__main__":
    main()