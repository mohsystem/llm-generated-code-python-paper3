
import re
from typing import Optional, Set

class Task107:
    SAFE_JNDI_PATTERN = re.compile(r'^[a-zA-Z0-9/_:-]+$')
    ALLOWED_CONTEXTS = {
        'java:comp/env/jdbc/',
        'java:comp/env/jms/',
        'java:comp/env/mail/'
    }
    
    @staticmethod
    def perform_secure_jndi_lookup(jndi_name: str) -> Optional[object]:
        """\n        Performs a secure JNDI lookup with validation\n        Note: Python doesn't have native JNDI, this is a simulation\n        """
        if not jndi_name:
            print("Error: JNDI name cannot be null or empty")
            return None
        
        # Validate JNDI name format
        if not Task107.SAFE_JNDI_PATTERN.match(jndi_name):
            print(f"Error: Invalid JNDI name format: {jndi_name}")
            return None
        
        # Check if JNDI name starts with allowed context
        is_allowed = any(jndi_name.startswith(ctx) for ctx in Task107.ALLOWED_CONTEXTS)
        
        if not is_allowed:
            print(f"Error: JNDI context not allowed: {jndi_name}")
            return None
        
        # Simulate JNDI lookup (Python doesn't have native JNDI)\n        try:\n            print(f"Successfully validated JNDI name: {jndi_name}")\n            # In real scenario, this would connect to naming service\n            return {"jndi_name": jndi_name, "status": "simulated_resource"}\n        except Exception as e:\n            print(f"JNDI Lookup failed for: {jndi_name} - {str(e)}")\n            return None\n    \n    @staticmethod\n    def is_valid_jndi_name(jndi_name: str) -> bool:\n        """Validates if a JNDI name is safe and allowed"""\n        if not jndi_name:\n            return False\n        \n        if not Task107.SAFE_JNDI_PATTERN.match(jndi_name):\n            return False\n        \n        return any(jndi_name.startswith(ctx) for ctx in Task107.ALLOWED_CONTEXTS)\n\n\nif __name__ == "__main__":\n    print("=== Secure JNDI Lookup Program ===\\n")\n    \n    # Test Case 1: Valid JDBC lookup\n    print("Test 1: Valid JDBC lookup")\n    Task107.perform_secure_jndi_lookup("java:comp/env/jdbc/myDataSource")\n    \n    # Test Case 2: Valid JMS lookup\n    print("\\nTest 2: Valid JMS lookup")\n    Task107.perform_secure_jndi_lookup("java:comp/env/jms/myQueue")\n    \n    # Test Case 3: Invalid characters (injection attempt)\n    print("\\nTest 3: Invalid characters (security test)")\n    Task107.perform_secure_jndi_lookup("java:comp/env/jdbc/../../../malicious")\n    \n    # Test Case 4: Unauthorized context\n    print("\\nTest 4: Unauthorized context")\n    Task107.perform_secure_jndi_lookup("rmi://malicious.server/Exploit")\n    \n    # Test Case 5: Empty JNDI name\n    print("\\nTest 5: Empty JNDI name")\n    Task107.perform_secure_jndi_lookup("")\n    \n    # Test validation function\n    print("\\n=== JNDI Name Validation Tests ===")\n    print(f"Valid name: {Task107.is_valid_jndi_name('java:comp/env/jdbc/testDB')}")\n    print(f"Invalid name: {Task107.is_valid_jndi_name('ldap://evil.com/exploit')}")
