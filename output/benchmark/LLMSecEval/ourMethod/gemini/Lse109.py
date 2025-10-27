import sys
import re

# A whitelist pattern for valid usernames.
# Allows alphanumeric characters, underscore, dot, and hyphen.
# This helps prevent command injection and other injection attacks.
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
PASSWD_FILE = "/etc/passwd"

def get_user_info(username):
    """
    Finds and returns the line for a given username from /etc/passwd.
    This implementation reads the file directly to avoid command injection vulnerabilities
    that would arise from executing external shell commands with user input.
    
    Args:
        username: The username to search for.
    
    Returns:
        The line from /etc/passwd or None if not found or input is invalid.
    """
    if not isinstance(username, str) or not USERNAME_PATTERN.match(username):
        print("Error: Invalid username format provided.", file=sys.stderr)
        return None

    try:
        with open(PASSWD_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                # /etc/passwd format is username:password:UID:GID:...
                try:
                    parts = line.split(':', 1)
                    if parts[0] == username:
                        return line.strip()
                except IndexError:
                    # Ignore malformed lines in the passwd file
                    continue
    except FileNotFoundError:
        print(f"Error: {PASSWD_FILE} not found.", file=sys.stderr)
    except PermissionError:
        print(f"Error: Insufficient permissions to read {PASSWD_FILE}.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        
    return None

def run_tests():
    """ Runs a set of predefined test cases. """
    test_usernames = [
        "root",                 # Test case 1: A common existing user
        "daemon",               # Test case 2: Another common user
        "nonexistentuser12345", # Test case 3: A non-existent user
        "root;whoami",          # Test case 4: A malicious input pattern
        ""                      # Test case 5: An empty input
    ]

    for test_user in test_usernames:
        print(f"Searching for user: \"{test_user}\"")
        result = get_user_info(test_user)
        if result:
            print(f"Found: {result}")
        else:
            print("Result: Not found or invalid input.")
        print("---------------------------------")

def main():
    """ Main function to handle command line arguments and run tests. """
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <username>")
        print("\n--- Running Internal Test Cases ---")
        run_tests()
        return

    username = sys.argv[1]
    user_info = get_user_info(username)
    if user_info:
        print(user_info)
    else:
        print(f"User '{username}' not found or input was invalid.")

if __name__ == "__main__":
    main()