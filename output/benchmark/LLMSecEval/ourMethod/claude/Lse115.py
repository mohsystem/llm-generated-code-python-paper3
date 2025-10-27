
# Python implementation
# SECURITY NOTE: This code demonstrates the UNSAFE pattern described in the prompt.
# Using shell=True or unsanitized input creates command injection vulnerabilities (CWE-78).
# This implementation uses subprocess with argument list (NOT shell) and strict validation.

import subprocess
import re
from typing import Optional

def execute_command(directory: str) -> str:
    """\n    Securely execute ls command with strict input validation.\n    \n    Args:\n        directory: Directory name to list (validated, no paths)\n    \n    Returns:\n        Command output or error message\n    """
    # Input validation: reject None or empty
    if not directory or not isinstance(directory, str):
        return "Error: Invalid directory parameter"
    
    # Length check: prevent excessive input
    if len(directory) > 255:
        return "Error: Directory name too long"
    
    # Sanitization: block shell metacharacters and path traversal
    # Reject: ; | & $ ` \\ " ' < > ( ) { } [ ] * ? ~ ! # % ^\n    if re.search(r'[;&|`$\\\\"\\'<>(){}[\\]*?~!#%^]', directory) or '..' in directory or directory.startswith('/'):\n        return "Error: Invalid characters in directory path"\n    \n    # Whitelist validation: only alphanumeric, hyphens, underscores\n    if not re.match(r'^[a-zA-Z0-9_-]+$', directory):\n        return "Error: Directory name contains invalid characters"\n    \n    try:\n        # Use subprocess with argument list (shell=False by default)\n        # This prevents shell interpretation and injection attacks\n        result = subprocess.run(\n            ['ls', '-la', directory],\n            capture_output=True,\n            text=True,\n            timeout=5,  # Timeout to prevent hanging\n            check=False,\n            env={}  # Empty environment for security\n        )\n        \n        if result.returncode != 0:\n            return f"Error: Command failed with exit code {result.returncode}"\n        \n        return result.stdout\n        \n    except subprocess.TimeoutExpired:\n        return "Error: Command execution timeout"\n    except Exception:\n        # Generic error - do not leak internal details\n        return "Error: Command execution failed"\n\ndef main():\n    """Test cases demonstrating secure execution and validation."""\n    \n    print("Test 1 - Valid directory:")\n    print(execute_command("testdir"))\n    print()\n    \n    print("Test 2 - Valid directory with underscore:")\n    print(execute_command("my_folder"))\n    print()\n    \n    print("Test 3 - Invalid: path traversal attempt:")\n    print(execute_command("../etc"))\n    print()\n    \n    print("Test 4 - Invalid: command injection attempt:")\n    print(execute_command("test; rm -rf /"))\n    print()\n    \n    print("Test 5 - Invalid: pipe attempt:")\n    print(execute_command("test | cat /etc/passwd"))\n\nif __name__ == "__main__":
    main()
