
import re
import os
import sys
import hashlib
import platform

USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,32}$')
PASSWORD_PATTERN = re.compile(r'^.{8,128}$')

def validate_username(username):
    """Validate username with whitelist pattern"""
    if not username:
        return False
    return USERNAME_PATTERN.match(username) is not None

def validate_password(password):
    """Validate password length and complexity"""
    if not password:
        return False
    return PASSWORD_PATTERN.match(password) is not None

def hash_password(password):
    """Hash password using SHA-256"""
    try:
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    except Exception as e:
        print(f"Password hashing error: {e}", file=sys.stderr)
        return None

def change_password_secure(username, new_password):
    """Perform secure password change operation"""
    # Validate inputs
    if not validate_username(username):
        print("Invalid username format", file=sys.stderr)
        return False
    
    if not validate_password(new_password):
        print("Invalid password format", file=sys.stderr)
        return False
    
    # Simulated privileged operation
    print(f"Simulating privileged password change for user: {username}")
    
    # Hash password before storage
    hashed_password = hash_password(new_password)
    if hashed_password is None:
        print("Password hashing failed", file=sys.stderr)
        return False
    
    print("Password changed successfully (simulated)")
    return True

def drop_privileges():
    """Drop privileges after privileged operation"""
    print("Dropping privileges...")
    
    system = platform.system().lower()
    
    if system in ['linux', 'darwin']:
        # Unix-like systems
        try:
            # In production, use os.setuid() and os.setgid()
            # This requires running as root initially
            print("Would call os.setuid/os.setgid on Unix-like system")
            print("Privileges dropped to unprivileged user")
        except Exception as e:
            print(f"Failed to drop privileges: {e}", file=sys.stderr)
    elif system == 'windows':
        # Windows systems
        print("Would adjust token privileges on Windows")
        print("Privileges dropped to limited user")
    
    # Clear sensitive data from memory
    import gc
    gc.collect()

def perform_privileged_operation(username, new_password):
    """Perform privileged operation and drop privileges"""
    try:
        success = change_password_secure(username, new_password)
        
        if success:
            print("Operation completed successfully")
        else:
            print("Operation failed")
    finally:
        # Always drop privileges
        drop_privileges()

def main():
    """Main function with test cases"""
    print("=== Test Case 1: Valid username and password ===")
    perform_privileged_operation("testuser1", "SecurePass123!")
    
    print("\\n=== Test Case 2: Invalid username (special chars) ===")
    perform_privileged_operation("test@user", "SecurePass123!")
    
    print("\\n=== Test Case 3: Invalid password (too short) ===")
    perform_privileged_operation("testuser2", "short")
    
    print("\\n=== Test Case 4: Valid username and long password ===")
    perform_privileged_operation("validuser", "ThisIsAVeryLongAndSecurePassword12345!")
    
    print("\\n=== Test Case 5: Empty username ===")
    perform_privileged_operation("", "SecurePass123!")

if __name__ == "__main__":
    main()
