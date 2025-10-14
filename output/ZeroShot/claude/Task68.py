
import ldap
import sys

def search_ldap(dc_component, username):
    result = []
    
    try:
        # Connect to LDAP server
        ldap_connection = ldap.initialize('ldap://localhost:389')
        ldap_connection.set_option(ldap.OPT_REFERRALS, 0)
        
        # Anonymous bind
        ldap_connection.simple_bind_s()
        
        # Construct base DN from DC component
        base_dn = "dc=" + dc_component.replace(".", ",dc=")
        
        # Construct LDAP search filter (VULNERABLE TO INJECTION)
        search_filter = f"(uid={username})"
        
        # Define attributes to retrieve (None means all attributes)
        attributes = None
        
        # Perform search
        search_results = ldap_connection.search_s(
            base_dn,
            ldap.SCOPE_SUBTREE,
            search_filter,
            attributes
        )
        
        # Process results
        for dn, attrs in search_results:
            if dn:
                result.append(f"DN: {dn}")
                for attr_name, attr_values in attrs.items():
                    for value in attr_values:
                        try:
                            decoded_value = value.decode('utf-8')
                        except:
                            decoded_value = str(value)
                        result.append(f"{attr_name}: {decoded_value}")
                result.append("")
        
        ldap_connection.unbind_s()
        
        if not result:
            result.append("No user found")
            
    except Exception as e:
        result.append(f"Error: {str(e)}")
    
    return "\\n".join(result)

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    print(search_ldap("example.com", "john.doe"))
    print("---")
    
    print("Test Case 2:")
    print(search_ldap("company.org", "admin"))
    print("---")
    
    print("Test Case 3:")
    print(search_ldap("test.local", "user123"))
    print("---")
    
    print("Test Case 4:")
    print(search_ldap("domain.net", "testuser"))
    print("---")
    
    print("Test Case 5:")
    print(search_ldap("myorg.com", "employee"))
    print("---")
    
    # Command line argument handling
    if len(sys.argv) >= 3:
        print("\\nCommand Line Arguments:")
        print(search_ldap(sys.argv[1], sys.argv[2]))
