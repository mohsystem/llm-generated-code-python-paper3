
import sys
try:
    import ldap
except ImportError:
    ldap = None

def search_ldap_user(domain_component, username):
    if ldap is None:
        return "Error: python-ldap module not installed. Install with: pip install python-ldap"
    
    result = []
    
    try:
        # Connect to LDAP server
        ldap_client = ldap.initialize("ldap://localhost:389")
        ldap_client.set_option(ldap.OPT_REFERRALS, 0)
        
        # Construct the base DN from domain component
        base_dn = "dc=" + domain_component.replace(".", ",dc=")
        
        # Construct the search filter
        search_filter = f"(uid={username})"
        
        # Perform search
        search_results = ldap_client.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)
        
        if search_results:
            for dn, attributes in search_results:
                result.append(f"User found: {dn}")
                result.append("Attributes:")
                for attr_name, attr_values in attributes.items():
                    for value in attr_values:
                        if isinstance(value, bytes):
                            value = value.decode('utf-8', errors='ignore')
                        result.append(f"  {attr_name}: {value}")
        else:
            result.append("User not found")
        
        ldap_client.unbind_s()
        
    except Exception as e:
        result.append(f"Error: {str(e)}")
    
    return "\\n".join(result)


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        domain_component = sys.argv[1]
        username = sys.argv[2]
        print(search_ldap_user(domain_component, username))
    else:
        # Test cases
        print("Test Case 1:")
        print(search_ldap_user("example.com", "john.doe"))
        print("\\n---\\n")
        
        print("Test Case 2:")
        print(search_ldap_user("company.org", "alice"))
        print("\\n---\\n")
        
        print("Test Case 3:")
        print(search_ldap_user("test.local", "bob.smith"))
        print("\\n---\\n")
        
        print("Test Case 4:")
        print(search_ldap_user("domain.net", "admin"))
        print("\\n---\\n")
        
        print("Test Case 5:")
        print(search_ldap_user("mycompany.com", "testuser"))
