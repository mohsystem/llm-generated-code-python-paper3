# NOTE: Requires the 'python-ldap' library. Install with: pip install python-ldap
# NOTE: This program requires a running LDAP server on localhost:389 with appropriate data.

import sys
import ldap
import ldap.filter

def search_ldap_user(username, domain_component):
    """
    Searches for a user in an LDAP directory. This function demonstrates secure
    practices by using ldap.filter.escape_filter_chars to prevent LDAP injection.

    Args:
        username (str): The username (uid) to search for.
        domain_component (str): The domain component string, e.g., "example,com".
        
    Returns:
        str: A string containing the search results, or an error message.
    """
    conn = None
    ldap_uri = 'ldap://localhost:389'

    try:
        # --- 1. Initialize connection to LDAP server ---
        # For production, use 'ldaps://...' and configure TLS options.
        conn = ldap.initialize(ldap_uri)
        conn.protocol_version = ldap.VERSION3

        # Use an anonymous bind for this example. For production, use simple_bind_s 
        # with a dedicated service account DN and password.
        conn.simple_bind_s()

        # --- 2. Construct the search base from domain components ---
        # Basic validation on the domain component format to ensure it contains valid characters.
        if not all(c.isalnum() or c in ',.-' for c in domain_component):
             return "Error: Invalid characters in domain component."
        search_base = "dc=" + domain_component.replace(",", ",dc=")

        # --- 3. Escape the username to prevent LDAP injection ---
        # This is the crucial security step for building the filter string safely.
        escaped_username = ldap.filter.escape_filter_chars(username)
        search_filter = f"(uid={escaped_username})"

        # --- 4. Specify attributes to return ---
        # This prevents leaking sensitive or unnecessary information.
        attributes_to_return = ['cn', 'sn', 'mail', 'uid']

        # --- 5. Perform the search ---
        # search_s is a synchronous search.
        search_results = conn.search_s(search_base, ldap.SCOPE_SUBTREE, search_filter, attributes_to_return)
        
        result_builder = []
        if not search_results:
            return f"User '{username}' not found in '{search_base}'."
        
        result_builder.append(f"Search results for user '{username}':\n")
        for dn, entry in search_results:
            if dn: # Ignore search continuation references which can be part of the result
                result_builder.append(f">> DN: {dn}\n")
                for attr_name, attr_values in entry.items():
                    # Decode values from bytes to string for printing
                    decoded_values = [val.decode('utf-8') for val in attr_values]
                    result_builder.append(f"   {attr_name}: {' '.join(decoded_values)}\n")

        return "".join(result_builder)

    except ldap.LDAPError as e:
        # In a production app, log the error details rather than returning them to the user.
        return f"Error during LDAP search: {e}"
    finally:
        # --- 6. Unbind the connection to release resources ---
        if conn:
            conn.unbind_s()

def main():
    if len(sys.argv) == 3:
        print("--- Running with Command Line Arguments ---")
        username = sys.argv[1]
        dc = sys.argv[2]
        print(search_ldap_user(username, dc))
    else:
        print("Usage: python script_name.py <username> <domain_component_string>")
        print("Example: python script_name.py jdoe example,com\n")
        print("NOTE: This program requires a running LDAP server on localhost:389 with appropriate data.\n")
        
        # --- 5 Hardcoded Test Cases ---
        print("--- Running 5 Hardcoded Test Cases ---")

        # Test Case 1: A valid user that should exist on the test server.
        print("--- Test Case 1: Valid User ---")
        print(search_ldap_user("jdoe", "example,com"))

        # Test Case 2: A user that should not exist.
        print("--- Test Case 2: Non-existent User ---")
        print(search_ldap_user("nonexistentuser", "example,com"))

        # Test Case 3: A user in a different domain component.
        print("--- Test Case 3: User in a different DC ---")
        print(search_ldap_user("asmith", "test,org"))
        
        # Test Case 4: An attempt at LDAP injection. The escaping should handle this safely.
        print("--- Test Case 4: Potential Injection Attempt ---")
        print(search_ldap_user("jdoe)(uid=*", "example,com"))

        # Test Case 5: Invalid domain component format.
        print("--- Test Case 5: Invalid Domain Component ---")
        print(search_ldap_user("jdoe", "ex@mple,com"))

if __name__ == "__main__":
    main()