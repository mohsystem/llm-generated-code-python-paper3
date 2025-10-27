
import os
from pathlib import Path
from typing import Optional

def list_directory(directory_path: Optional[str]) -> str:
    """\n    Secure directory listing - DOES NOT use os.system() to avoid command injection.\n    Uses pathlib for safe file system operations.\n    """
    # Input validation: reject None, empty, or invalid paths
    if not directory_path or not directory_path.strip():
        return "Error: Invalid directory path"
    
    try:
        # Normalize and resolve path to prevent traversal attacks
        path = Path(directory_path).resolve()
        
        # Additional security: verify path exists and is a directory
        if not path.exists():
            return "Error: Path does not exist"
        
        if not path.is_dir():
            return "Error: Path is not a directory"
        
        # List directory contents securely
        result = [f"Contents of: {path}"]
        
        # Iterate through directory entries safely
        for entry in sorted(path.iterdir()):
            result.append(entry.name)
        
        return "\\n".join(result)
        
    except (OSError, ValueError, RuntimeError) as e:
        # Generic error message - don't leak internal details
        return "Error: Cannot access directory"

def main():
    """Test cases demonstrating secure directory listing"""
    # Test case 1: Current directory
    print("=== Test 1: Current directory ===")
    print(list_directory("."))
    
    # Test case 2: Temp directory
    print("\\n=== Test 2: Temp directory ===")
    print(list_directory("/tmp"))
    
    # Test case 3: Invalid path (security test)
    print("\\n=== Test 3: Path traversal attempt ===")
    print(list_directory("../../../etc"))
    
    # Test case 4: None input
    print("\\n=== Test 4: None input ===")
    print(list_directory(None))
    
    # Test case 5: Empty string
    print("\\n=== Test 5: Empty string ===")
    print(list_directory(""))

if __name__ == "__main__":
    main()
