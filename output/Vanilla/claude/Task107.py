
# Note: Python does not have native JNDI support as it's a Java technology.
# This implementation simulates JNDI functionality using a dictionary-based registry.

class JNDISimulator:
    def __init__(self):
        self.registry = {}
    
    def bind_resource(self, jndi_name, resource):
        """Bind a resource to a JNDI name"""
        try:
            self.registry[jndi_name] = resource
            print(f"Successfully bound: {jndi_name}")
            return True
        except Exception as e:
            print(f"Failed to bind: {jndi_name}")
            print(f"Error: {str(e)}")
            return False
    
    def perform_jndi_lookup(self, jndi_name):
        """Perform a JNDI lookup to retrieve a resource"""
        try:
            if jndi_name in self.registry:
                return self.registry[jndi_name]
            else:
                print(f"JNDI Lookup failed for: {jndi_name}")
                print(f"Error: Resource not found")
                return None
        except Exception as e:
            print(f"JNDI Lookup failed for: {jndi_name}")
            print(f"Error: {str(e)}")
            return None
    
    def list_bindings(self, context_name):
        """List all bindings in a context"""
        print(f"Bindings in context: {context_name}")
        for name, resource in self.registry.items():
            if name.startswith(context_name):
                print(f"  Name: {name}, Type: {type(resource).__name__}")
    
    def unbind_resource(self, jndi_name):
        """Unbind a resource from JNDI name"""
        try:
            if jndi_name in self.registry:
                del self.registry[jndi_name]
                print(f"Successfully unbound: {jndi_name}")
                return True
            else:
                print(f"Resource not found: {jndi_name}")
                return False
        except Exception as e:
            print(f"Failed to unbind: {jndi_name}")
            print(f"Error: {str(e)}")
            return False


def main():
    print("=== JNDI Lookup Simulation (Python) ===\\n")
    
    jndi = JNDISimulator()
    
    # Test Case 1: Bind and lookup a String
    print("Test Case 1: String Resource")
    test_string = "Hello JNDI World"
    jndi.bind_resource("test/string", test_string)
    result1 = jndi.perform_jndi_lookup("test/string")
    print(f"Retrieved: {result1}")
    print()
    
    # Test Case 2: Bind and lookup an Integer
    print("Test Case 2: Integer Resource")
    test_integer = 12345
    jndi.bind_resource("test/integer", test_integer)
    result2 = jndi.perform_jndi_lookup("test/integer")
    print(f"Retrieved: {result2}")
    print()
    
    # Test Case 3: Bind and lookup a dictionary
    print("Test Case 3: Dictionary Object")
    test_dict = {"key1": "value1", "key2": "value2"}
    jndi.bind_resource("test/dict", test_dict)
    result3 = jndi.perform_jndi_lookup("test/dict")
    print(f"Retrieved: {result3}")
    print()
    
    # Test Case 4: List all bindings
    print("Test Case 4: List Bindings")
    jndi.list_bindings("test")
    print()
    
    # Test Case 5: Lookup non-existent resource
    print("Test Case 5: Non-existent Resource")
    result5 = jndi.perform_jndi_lookup("test/nonexistent")
    print(f"Retrieved: {result5}")


if __name__ == "__main__":
    main()
