
import re
from typing import Any, Optional

# Simulate JNDI context for demonstration purposes
class SecureJNDIContext:
    SAFE_JNDI_PATTERN = re.compile(r'^java:comp/env/[a-zA-Z0-9/_-]+$')
    ALLOWED_SCHEMES = frozenset(['java:comp/env'])
    
    def __init__(self):
        self._resources = {}
    
    def lookup(self, jndi_name: str) -> Optional[Any]:
        """\n        Performs a secure JNDI lookup with validation\n        \n        Args:\n            jndi_name: The JNDI name to lookup\n            \n        Returns:\n            The resource if found, None otherwise\n            \n        Raises:\n            ValueError: If the JNDI name is invalid or potentially dangerous\n        """
        if not jndi_name or not isinstance(jndi_name, str):
            raise ValueError("JNDI name must be a non-empty string")
        
        trimmed_name = jndi_name.strip()
        
        if not trimmed_name:
            raise ValueError("JNDI name cannot be empty or whitespace only")
        
        # Validate JNDI name format - only allow safe local lookups
        if not self.SAFE_JNDI_PATTERN.match(trimmed_name):
            raise ValueError(
                "Invalid JNDI name format. Only java:comp/env/ namespace allowed"
            )
        
        # Check for path traversal attempts
        if '..' in trimmed_name or '//' in trimmed_name:
            raise ValueError("Path traversal detected in JNDI name")
        
        # Check scheme
        scheme_valid = False
        for allowed_scheme in self.ALLOWED_SCHEMES:
            if trimmed_name.startswith(allowed_scheme):
                scheme_valid = True
                break
        
        if not scheme_valid:
            raise ValueError("JNDI scheme not allowed")
        
        # Simulate lookup (in real implementation, this would interact with JNDI)
        result = self._resources.get(trimmed_name)
        
        return result
    
    def bind(self, jndi_name: str, obj: Any) -> None:
        """Bind an object for testing purposes"""
        if self.SAFE_JNDI_PATTERN.match(jndi_name):
            self._resources[jndi_name] = obj


def safe_jndi_lookup(jndi_name: str) -> Optional[Any]:
    """\n    Public interface for safe JNDI lookup\n    \n    Args:\n        jndi_name: The JNDI name to lookup\n        \n    Returns:\n        The resource if found, None otherwise\n    """
    try:
        context = SecureJNDIContext()
        return context.lookup(jndi_name)
    except ValueError as e:
        print(f"Lookup failed: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def main() -> None:
    print("JNDI Secure Lookup Examples:")
    print("=" * 50)
    
    # Test case 1: Valid JNDI name
    test_name1 = "java:comp/env/jdbc/myDataSource"
    print(f"\\nTest 1 - Valid name: {test_name1}")
    result = safe_jndi_lookup(test_name1)
    print(f"Result: {'Success (simulated)' if result is None else result}")
    
    # Test case 2: Invalid scheme
    test_name2 = "ldap://malicious.com/exploit"
    print(f"\\nTest 2 - Invalid scheme: {test_name2}")
    result = safe_jndi_lookup(test_name2)
    print(f"Result: {result}")
    
    # Test case 3: Path traversal attempt
    test_name3 = "java:comp/env/../../../etc/passwd"
    print(f"\\nTest 3 - Path traversal: {test_name3}")
    result = safe_jndi_lookup(test_name3)
    print(f"Result: {result}")
    
    # Test case 4: None input
    test_name4 = None
    print(f"\\nTest 4 - None input: {test_name4}")
    result = safe_jndi_lookup(test_name4)
    print(f"Result: {result}")
    
    # Test case 5: Empty string
    test_name5 = ""
    print(f"\\nTest 5 - Empty string: '{test_name5}'")
    result = safe_jndi_lookup(test_name5)
    print(f"Result: {result}")


if __name__ == "__main__":
    main()
