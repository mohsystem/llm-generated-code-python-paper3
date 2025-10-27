
import subprocess
import re

class Lse108:
    VALID_USERNAME = re.compile(r'^[a-zA-Z0-9_-]{1,32}$')
    
    @staticmethod
    def get_passwd_info(username):
        """\n        Safely retrieves user information using getent passwd command\n        """
        # Input validation to prevent command injection
        if not username or not Lse108.VALID_USERNAME.match(username):
            return "Error: Invalid username format"
        
        try:
            # Use subprocess with list arguments (safer than shell=True)
            result = subprocess.run(
                ['getent', 'passwd', username],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: User not found or command failed"
                
        except subprocess.TimeoutExpired:
            return "Error: Command timeout"
        except Exception as e:
            return f"Error: {str(e)}"


def main():
    lse = Lse108()
    
    # Test cases
    print("Test 1 - Valid user 'root':")
    print(lse.get_passwd_info('root'))
    
    print("\\nTest 2 - Valid user 'nobody':")
    print(lse.get_passwd_info('nobody'))
    
    print("\\nTest 3 - Invalid user with special chars '; rm -rf /':")
    print(lse.get_passwd_info('; rm -rf /'))
    
    print("\\nTest 4 - Empty username:")
    print(lse.get_passwd_info(''))
    
    print("\\nTest 5 - Null username:")
    print(lse.get_passwd_info(None))


if __name__ == "__main__":
    main()
