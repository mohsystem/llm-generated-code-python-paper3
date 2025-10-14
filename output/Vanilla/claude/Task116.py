
import os
import sys
import subprocess
import platform

class Task116:
    @staticmethod
    def change_user_password(username, new_password):
        try:
            # Check if running with elevated privileges
            if not Task116.has_elevated_privileges():
                print("Error: Insufficient privileges to change password")
                return False
            
            # Perform privileged operation
            print(f"Performing privileged operation: Changing password for user: {username}")
            
            os_name = platform.system().lower()
            
            if os_name == "windows":
                # Windows: net user command
                cmd = ["net", "user", username, new_password]
            else:
                # Linux/Unix: chpasswd command
                cmd = ["bash", "-c", f"echo '{username}:{new_password}' | chpasswd"]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"Password changed successfully for user: {username}")
                
                # Drop privileges after privileged operation
                Task116.drop_privileges()
                
                return True
            else:
                print(f"Failed to change password. Error: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"Error changing password: {str(e)}")
            return False
    
    @staticmethod
    def has_elevated_privileges():
        try:
            if platform.system().lower() == "windows":
                # Check if running as administrator on Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Check if running as root on Linux/Unix
                return os.geteuid() == 0
        except Exception:
            return False
    
    @staticmethod
    def drop_privileges():
        print("Dropping privileges...")
        
        try:
            os_name = platform.system().lower()
            
            if os_name == "windows":
                # Windows: Cannot truly drop privileges in Python, but we can note it
                print("Note: Privilege dropping on Windows requires process termination")
                print("Simulating privilege drop by restricting further operations")
            else:
                # Linux/Unix: Drop to regular user
                if os.geteuid() == 0:
                    # Get SUDO_UID if available (when run with sudo)
                    sudo_uid = os.environ.get('SUDO_UID')
                    sudo_gid = os.environ.get('SUDO_GID')
                    
                    if sudo_uid and sudo_gid:
                        # Drop to the original user
                        os.setgid(int(sudo_gid))
                        os.setuid(int(sudo_uid))
                        print(f"Privileges dropped to UID: {sudo_uid}, GID: {sudo_gid}")
                    else:
                        print("Running as root but no SUDO_UID available")
                else:
                    print("Not running with elevated privileges")
                    
        except Exception as e:
            print(f"Error dropping privileges: {str(e)}")


def main():
    print("=== Privilege Management Test Cases ===\\n")
    
    # Test Case 1: Valid user password change
    print("Test Case 1: Attempting to change password for testuser1")
    Task116.change_user_password("testuser1", "NewPass123!")
    print()
    
    # Test Case 2: Another user password change
    print("Test Case 2: Attempting to change password for testuser2")
    Task116.change_user_password("testuser2", "SecurePass456!")
    print()
    
    # Test Case 3: Different user
    print("Test Case 3: Attempting to change password for adminuser")
    Task116.change_user_password("adminuser", "AdminPass789!")
    print()
    
    # Test Case 4: Special characters in password
    print("Test Case 4: Attempting to change password with special characters")
    Task116.change_user_password("testuser3", "P@ssw0rd#Special!")
    print()
    
    # Test Case 5: Empty username
    print("Test Case 5: Attempting to change password with empty username")
    Task116.change_user_password("", "Password123!")
    print()


if __name__ == "__main__":
    main()
