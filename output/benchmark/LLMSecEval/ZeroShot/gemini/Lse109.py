import re
import os

# Regex for a typical, valid username.
VALID_USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
PASSWD_FILE = "/etc/passwd"

def get_user_info(username: str) -> str:
    """
    Securely retrieves a user's information from /etc/passwd by parsing the file.
    This avoids command injection vulnerabilities.

    Args:
        username: The username to search for.
    
    Returns:
        A string containing the user's line from /etc/passwd, or a message if not found or invalid.
    """
    if not isinstance(username, str) or not VALID_USERNAME_REGEX.match(username):
        return "Error: Invalid username format provided."

    if not os.path.exists(PASSWD_FILE):
        return f"Error: {PASSWD_FILE} not found. This program is intended for Unix-like systems."

    try:
        with open(PASSWD_FILE, 'r') as f:
            for line in f:
                # The format of /etc/passwd is `username:password:UID:GID:GECOS:home:shell`
                parts = line.split(':', 1)
                if parts[0] == username:
                    return line.strip()
    except IOError as e:
        return f"Error: Failed to read {PASSWD_FILE}. {e}"

    return f"User '{username}' not found."

def main():
    """ Main function with test cases. """
    test_users = [
        "root",                 # A user that should exist on most systems
        "nobody",               # Another common user
        "nonexistentuser123",   # A user that should not exist
        "daemon",               # A common system user
        "user;rm-rf/"           # An invalid/malicious username attempt
    ]

    for user in test_users:
        print(f"Searching for user: {user}")
        result = get_user_info(user)
        print(f"Result: {result}")
        print("--------------------")

if __name__ == "__main__":
    main()