
import re
import os

def get_user_info(username):
    """Secure method: Read and parse /etc/passwd directly"""
    if not username:
        return "Error: Username cannot be empty"
    
    # Validate username (alphanumeric, underscore, hyphen only)
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return "Error: Invalid username format"
    
    try:
        # Check if file exists
        if not os.path.exists('/etc/passwd'):
            return "Error: /etc/passwd not found"
        
        # Directly read the file without shell execution
        with open('/etc/passwd', 'r') as f:
            for line in f:
                if line.startswith(username + ':'):
                    return line.strip()
        return ""
        
    except PermissionError:
        return "Error: Permission denied"
    except Exception as e:
        return f"Error reading file: {str(e)}"

def main():
    """Main function with test cases"""
    test_users = ["root", "daemon", "nobody", "testuser", "admin"]
    
    print("=== User Information Lookup (Secure) ===\\n")
    
    for user in test_users:
        print(f"Searching for user: {user}")
        result = get_user_info(user)
        print(result if result else "User not found")
        print("---")

if __name__ == "__main__":
    main()
