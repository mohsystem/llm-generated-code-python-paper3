# python-ldap library is required. Install with: pip install python-ldap
import ldap
import sys

def search_ldap_user(base_dn, username):
    """
    Searches an LDAP directory for a user and returns their information.

    :param base_dn: The base DN for the search (e.g., "dc=example,dc=com").
    :param username: The username (uid) to search for.
    :return: A string containing the user's information, or an error message.
    """
    ldap_server = "ldap://localhost"
    result_str = ""
    conn = None
    
    try:
        # Initialize connection
        conn = ldap.initialize(ldap_server)
        conn.protocol_version = ldap.VERSION3

        # Perform an anonymous bind
        conn.simple_bind_s()

        search_filter = f"(&(objectClass=person)(uid={username}))"
        search_scope = ldap.SCOPE_SUBTREE

        results = conn.search_s(base_dn, search_scope, search_filter)

        if not results:
            return f"User '{username}' not found in '{base_dn}'.\n"

        for dn, entry in results:
            result_str += f"Found entry: {dn}\n"
            for attr_name, attr_values in entry.items():
                result_str += f"  Attribute: {attr_name}\n"
                for value in attr_values:
                    # Decode bytes to string for printing
                    result_str += f"    Value: {value.decode('utf-8')}\n"
        
        return result_str

    except ldap.LDAPError as e:
        return f"LDAP Error: {e}\n"
    finally:
        if conn:
            conn.unbind_s()

def main():
    """
    Main function to run test cases.
    """
    if len(sys.argv) > 1 and len(sys.argv) % 2 != 0:
        print("Running test cases from command line arguments...")
        args = sys.argv[1:]
        for i in range(0, len(args), 2):
            base_dn = args[i]
            username = args[i+1]
            print(f"--- Test Case {i//2 + 1}: base_dn={base_dn}, username={username} ---")
            result = search_ldap_user(base_dn, username)
            print(result)

    else:
        print("Running predefined test cases...")
        # Test Case 1: A standard valid user search
        print("--- Test Case 1: Find user 'jdoe' in 'dc=example,dc=com' ---")
        print(search_ldap_user("dc=example,dc=com", "jdoe"))

        # Test Case 2: Another valid user
        print("--- Test Case 2: Find user 'asmith' in 'dc=example,dc=com' ---")
        print(search_ldap_user("dc=example,dc=com", "asmith"))

        # Test Case 3: A user that does not exist
        print("--- Test Case 3: Find non-existent user 'nobody' ---")
        print(search_ldap_user("dc=example,dc=com", "nobody"))

        # Test Case 4: A search in a non-existent base DN
        print("--- Test Case 4: Search in a non-existent base DN ---")
        print(search_ldap_user("dc=nonexistent,dc=org", "jdoe"))

        # Test Case 5: A user in a different, valid base DN
        print("--- Test Case 5: Find user 'bcarter' in 'dc=test,dc=org' ---")
        print(search_ldap_user("dc=test,dc=org", "bcarter"))
        
        print("\nUsage for custom tests: python your_script_name.py <baseDn1> <user1> <baseDn2> <user2> ...")
        print("Example: python your_script_name.py dc=example,dc=com jdoe dc=example,dc=com nonexistant")

if __name__ == "__main__":
    main()