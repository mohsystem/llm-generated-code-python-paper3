import sys

def get_user_info(username):
    """
    Finds and returns a user's information from /etc/passwd.
    This function safely reads the file line by line to prevent command injection
    vulnerabilities that would arise from executing shell commands with user input.

    Args:
        username (str): The username to search for.
    
    Returns:
        str: The full line from /etc/passwd for the user, or a "not found" message.
    """
    # Basic validation to prevent invalid input
    if not username or not username.isalnum():
        # A simple alphanumeric check; real usernames can be more complex,
        # but this prevents many malicious inputs like '../' or ';'.
        if username and all(c.isalnum() or c in ('-', '_') for c in username):
            pass # Allow dashes and underscores
        else:
            return "Invalid username provided."

    passwd_file = "/etc/passwd"
    search_prefix = f"{username}:"
    
    try:
        # Using 'with' statement for automatic file closing
        with open(passwd_file, 'r') as f:
            for line in f:
                if line.startswith(search_prefix):
                    return line.strip()
    except FileNotFoundError:
        return f"Error: {passwd_file} not found."
    except Exception as e:
        return f"An error occurred: {e}"
        
    return f"User '{username}' not found."

def main():
    """
    Main function to handle command-line arguments or run test cases.
    """
    # The original prompt asked for command-line argument processing.
    # If arguments are provided, we use them. Otherwise, we run test cases.
    if len(sys.argv) > 1:
        username = sys.argv[1]
        print(f"Searching for user from command line: {username}")
        print(get_user_info(username))
    else:
        # Running 5 test cases as requested.
        print("--- Running Test Cases ---")
        test_users = ["root", "daemon", "nobody", "nonexistentuser123", "adm"]
        
        for user in test_users:
            print(f"\nSearching for user: {user}")
            result = get_user_info(user)
            print(f"Result: {result}")
            
        print("\n--- Test Cases Finished ---")
        print("You can also run this program with a command-line argument, e.g., python your_script_name.py root")

if __name__ == "__main__":
    main()