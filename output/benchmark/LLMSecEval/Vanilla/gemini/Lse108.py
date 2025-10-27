import os
import sys

def get_user_info(username: str) -> str:
    """
    Executes 'getent passwd <username>' using os.system() and returns the output.
    Output is captured by redirecting it to a temporary file.
    Note: A more Pythonic way would be to use the 'subprocess' module,
    but this implementation adheres to the prompt's 'system()' constraint.
    """
    # Basic sanitization to prevent command injection
    if not username.isalnum() and '_' not in username and '-' not in username:
        return ""
        
    temp_file_name = "py_getent_output.tmp"
    # Quote username to handle it as a single argument in the shell
    command = f"getent passwd \"{username}\" > {temp_file_name}"
    
    try:
        # system() executes the command in a subshell
        exit_code = os.system(command)
        
        if os.path.exists(temp_file_name):
            with open(temp_file_name, 'r') as f:
                content = f.read()
            return content
        else:
            return ""
    finally:
        if os.path.exists(temp_file_name):
            os.remove(temp_file_name)

def main():
    """ Main function with test cases """
    test_usernames = [
        "root",
        "daemon",
        "nonexistentuser12345",
        os.environ.get("USER", "nobody"), # Use current user or 'nobody' as fallback
        ""
    ]

    print("--- Python Test Cases ---")
    for user in test_usernames:
        print(f'Testing for user: "{user}"')
        output = get_user_info(user)
        if not output:
            print("Output: <No output or user not found>")
        else:
            print(f"Output: {output}", end="")
        print("-------------------------")

if __name__ == "__main__":
    main()