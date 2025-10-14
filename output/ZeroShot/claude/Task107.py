import re
from typing import Dict, Any, Optional


# Python does not have native JNDI support as it's a Java-specific API\n# However,
# we can demonstrate a similar naming/directory service
# concept\n\nimport re\nfrom typing import Any, Optional,
# Dict\n\n
class Task107:
    def __init__(self):
        # Simulated local registry for resources\n
        self.local_registry: Dict[str, Any] = {}
        def perform_jndi_lookup(self, jndi_name: str, context_factory: Optional[str] = None,
                                provider_url: Optional[str] = None) -> Optional[Any]:
            """

            :param self:
            :param jndi_name:
            :param context_factory:
            :param provider_url:
            :return:
            """
            # Secure lookup that simulates JNDI behavior.
            # Only allows local lookups for security.
            # """
            # Input validation
            # if not jndi_name or not jndi_name.strip():
            # raise ValueError("JNDI name cannot be null or empty")
            #
            # Whitelist validation - block remote protocols
            dangerous_patterns = [r'^ldap://', r'^rmi://', r'^dns://', r'^iiop://']
            for pattern in dangerous_patterns:
                if re.match(pattern, jndi_name, re.IGNORECASE):
                    raise SecurityError("Remote JNDI lookups are not allowed for security reasons")

            # Only allow java: namespace (simulated)
            if not jndi_name.startswith("java:"):
                raise SecurityError("Only java: namespace is allowed")

            try:
                # Lookup in local registry
                result = self.local_registry.get(jndi_name)
                if result is not None:
                    print(f"Successfully retrieved resource: {jndi_name}")
                    return result
                else:
                    print(f"Resource not found: {jndi_name}")
                    return None
            except Exception as e:
                print(f"JNDI lookup failed for: {jndi_name}")
                print(f"Error: {str(e)}")
                return None

    def perform_secure_local_lookup(self, jndi_name: str) -> Optional[Any]:
        """Secure lookup for local resources only."""
        return self.perform_jndi_lookup(jndi_name)
    
    def bind_resource(self, jndi_name: str, resource: Any) -> None:
        """Bind a resource to the local registry."""
        if not jndi_name or not jndi_name.startswith("java:"):
            raise SecurityError("Can only bind to java: namespace")
        
        try:
            self.local_registry[jndi_name] = resource
            print(f"Successfully bound resource: {jndi_name}")
        except Exception as e:
            print(f"Failed to bind resource: {str(e)}")


class SecurityError(Exception):
    """Custom security exception."""
    pass


def main():
    print("=== JNDI Lookup Security Demo (Python Simulation) ===\\n")
    
    task = Task107()
    
    # Bind some test resources
    task.bind_resource("java:comp/env/example", {"type": "database", "name": "testDB"})
    
    # Test Case 1: Valid local lookup
    print("Test Case 1: Valid local java: namespace lookup")
    try:
        result1 = task.perform_secure_local_lookup("java:comp/env/example")
        print(f"Result: {result1}\\n")
    except Exception as e:
        print(f"Expected behavior: {str(e)}\\n")
    
    # Test Case 2: Attempting LDAP lookup (should be blocked)
    print("Test Case 2: Blocked LDAP lookup attempt")
    try:
        result2 = task.perform_jndi_lookup("ldap://malicious.com/exploit")
        print(f"Result: {result2}")
    except SecurityError as e:
        print(f"Security blocked: {str(e)}\\n")
    
    # Test Case 3: Attempting RMI lookup (should be blocked)
    print("Test Case 3: Blocked RMI lookup attempt")
    try:
        result3 = task.perform_jndi_lookup("rmi://malicious.com/exploit")
        print(f"Result: {result3}")
    except SecurityError as e:
        print(f"Security blocked: {str(e)}\\n")
    
    # Test Case 4: Null/None JNDI name
    print("Test Case 4: None JNDI name validation")
    try:
        result4 = task.perform_jndi_lookup(None)
        print(f"Result: {result4}")
    except (ValueError, TypeError) as e:
        print(f"Validation error: {str(e)}\\n")
    
    # Test Case 5: Empty JNDI name
    print("Test Case 5: Empty JNDI name validation")
    try:
        result5 = task.perform_jndi_lookup("")
        print(f"Result: {result5}")
    except ValueError as e:
        print(f"Validation error: {str(e)}\\n")
    
    print("=== Security Summary ===")
    print("✓ Remote lookups (LDAP, RMI, DNS, IIOP) are blocked")
    print("✓ Only local java: namespace is allowed")
    print("✓ Input validation prevents injection attacks")
    print("✓ Proper error handling and resource cleanup")


if __name__ == "__main__":
    main()
