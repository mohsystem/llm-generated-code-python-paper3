
import os
import re
from pathlib import Path

def get_user_info(username):
    """\n    Security: Read /etc/passwd directly instead of executing shell commands.\n    This prevents command injection (CWE-78) by avoiding subprocess calls.\n    """
    if not username:
        return "Error: Username cannot be empty"
    
    # Security: Validate username to contain only safe characters
    # Usernames should only contain alphanumeric, underscore, hyphen, and period
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return "Error: Invalid username format"
    
    # Security: Limit username length to prevent resource exhaustion
    if len(username) > 32:
        return "Error: Username too long"
    
    passwd_path = Path('/etc/passwd')
    
    # Security: Validate that /etc/passwd is a regular file, not a symlink
    # This prevents TOCTOU and symlink attacks
    try:
        if not passwd_path.is_file() or passwd_path.is_symlink():
            return "Error: /etc/passwd is not a regular file"
    except Exception:
        return "Error: Cannot access /etc/passwd"
    
    result = []
    
    # Security: Open file with explicit encoding and read directly
    # No shell command execution prevents injection attacks
    try:
        # Security: Use context manager for automatic resource cleanup
        with open(passwd_path, 'r', encoding='utf-8') as f:
            # Security: Limit lines read to prevent DoS
            max_lines = 10000
            line_count = 0
            
            for line in f:
                line_count += 1
                if line_count > max_lines:
                    break
                
                # Security: Validate line length to prevent memory issues
                if len(line) > 1024:
                    continue
                
                line = line.strip()
                if not line:
                    continue
                
                # Parse line format: username:password:uid:gid:gecos:home:shell
                fields = line.split(':', 1)
                if fields and fields[0] == username:
                    result.append(line)
        
        if not result:
            return f"User not found: {username}"
        
        return '\\n'.join(result)
        
    except IOError:
        return "Error: Cannot read /etc/passwd"
    except Exception:
        return "Error: Unexpected error reading file"

def main():
    """Test cases for user lookup"""
    test_users = ['root', 'daemon', 'bin', 'nonexistent', 'test.user']
    
    print("=== User Information Lookup ===\\n")
    
    for user in test_users:
        print(f"Looking up user: {user}")
        info = get_user_info(user)
        print(info)
        print("---")
    
    # If command line argument provided, use it
    import sys
    if len(sys.argv) > 1:
        print(f"\\nCommand line lookup: {sys.argv[1]}")
        print(get_user_info(sys.argv[1]))

if __name__ == "__main__":
    main()
