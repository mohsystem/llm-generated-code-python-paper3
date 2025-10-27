
import re
import os

USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,32}$')

def get_user_info(username):
    # Validate username to prevent injection attacks
    if not username or not USERNAME_PATTERN.match(username):
        return "Invalid username format"
    
    try:
        with open('/etc/passwd', 'r') as file:
            result = []
            for line in file:
                # Safely check if line starts with username followed by colon
                if line.startswith(username + ':'):
                    result.append(line.rstrip('\\n'))
            
            if result:
                return '\\n'.join(result)
            else:
                return "User not found"
    except FileNotFoundError:
        return "File not found: /etc/passwd"
    except IOError as e:
        return f"Error reading file: {e}"

def main():
    import sys
    
    # Test cases
    test_cases = ["root", "daemon", "nobody", "invalid@user", "testuser"]
    
    if len(sys.argv) > 1:
        print(get_user_info(sys.argv[1]))
    else:
        print("Running test cases:")
        for username in test_cases:
            print(f"\\n[Test: {username}]")
            print(get_user_info(username))

if __name__ == "__main__":
    main()
