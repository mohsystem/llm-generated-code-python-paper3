
import os
import re
from pathlib import Path
from typing import Optional

# Define allowed resources with their relative paths
RESOURCE_MAP = {
    "config": "config.txt",
    "data": "data.txt",
    "log": "log.txt",
    "report": "report.txt",
    "info": "info.txt"
}

# Set base directory to current working directory
BASE_DIRECTORY = Path.cwd().resolve()


def access_resource(resource_name: Optional[str]) -> str:
    """\n    Safely access a resource based on user input with proper validation.\n    \n    Args:\n        resource_name: Name of the resource to access\n        \n    Returns:\n        Content of the resource or error message\n    """
    if resource_name is None or not resource_name.strip():
        return "ERROR: Resource name cannot be null or empty"
    
    # Validate resource name format (alphanumeric and underscores only)
    if not re.match(r'^[a-zA-Z0-9_]+$', resource_name):
        return "ERROR: Invalid resource name format"
    
    # Check if resource exists in whitelist
    if resource_name not in RESOURCE_MAP:
        return "ERROR: Resource not found or access denied"
    
    relative_path = RESOURCE_MAP[resource_name]
    
    try:
        # Construct path safely
        requested_path = (BASE_DIRECTORY / relative_path).resolve()
        
        # Verify the resolved path is still within base directory
        if not str(requested_path).startswith(str(BASE_DIRECTORY)):
            return "ERROR: Path traversal attempt detected"
        
        # Check if path is a regular file (not symlink or directory)
        if not requested_path.is_file() or requested_path.is_symlink():
            return "ERROR: Resource is not a regular file"
        
        # Read file content safely
        with open(requested_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return content
        
    except (IOError, OSError, PermissionError):
        return "ERROR: Unable to access resource"
    except Exception:
        return "ERROR: Security violation"


def setup_test_files() -> None:
    """Create test files for demonstration purposes."""
    try:
        for filename in RESOURCE_MAP.values():
            filepath = BASE_DIRECTORY / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Content of {filename}")
    except Exception:
        print("Warning: Could not create test files")


def main() -> None:
    """Main function with test cases."""
    # Create test files for demonstration
    setup_test_files()
    
    # Test case 1: Valid resource access
    print("Test 1 - Access 'config':")
    print(access_resource("config"))
    print()
    
    # Test case 2: Valid resource access
    print("Test 2 - Access 'data':")
    print(access_resource("data"))
    print()
    
    # Test case 3: Non-existent resource
    print("Test 3 - Access 'secret':")
    print(access_resource("secret"))
    print()
    
    # Test case 4: Null/None input
    print("Test 4 - None input:")
    print(access_resource(None))
    print()
    
    # Test case 5: Invalid format (path traversal attempt)
    print("Test 5 - Path traversal attempt:")
    print(access_resource("../etc/passwd"))
    print()


if __name__ == "__main__":
    main()
