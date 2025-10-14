import sys
import ldap
import ldap.filter
import re
from typing import List

def find_user_in_ldap(user_input: str) -> str:
    """
    Extracts user and domain, connects to LDAP, and searches for the user.

    Args:
        user_input: A string in the format "username@domain.com".

    Returns:
        A string containing the search results or an error message.
    """
    if not user_input:
        return "Error: Input cannot be empty."

    # 1. Extract username and domain components
    parts = user_input.split('@', 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return "Error: Invalid input format. Expected 'username@domain.com'."
    
    username, domain = parts
    
    # 2. Validate inputs
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return "Error: Domain contains invalid characters."
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return "Error: Username contains invalid characters."

    # 3. Construct Base DN
    base_dn = "dc=" + domain.replace('.', ',dc=')

    # 4. Sanitize username for LDAP filter (LDAP Injection prevention)
    # Use the library's built-in escaping function, which is the safest method.
    escaped_username = ldap.filter.escape_filter_chars(username)
    search_filter = f"(uid={escaped_username})"

    ldap_uri = "ldap://localhost:389"
    conn = None
    result_builder: List[str] = []
    
    try:
        # 5. Connect and search LDAP
        conn = ldap.initialize(ldap_uri)
        # For production, use ldaps:// and set TLS options
        # conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        # conn.set_option(ldap.OPT_X_TLS_CACERTFILE, '/path/to/ca/cert.pem')
        
        conn.protocol_version = ldap.VERSION3
        
        # Anonymous bind
        conn.simple_bind_s("", "")
        
        result_builder.append(f"Searching for user '{username}' in '{base_dn}'")
        result_builder.append(f"Using filter: {search_filter}")
        
        results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter, None)
        
        if not results:
            result_builder.append("User not found.")
        else:
            for dn, entry in results:
                result_builder.append(f"Found entry: {dn}")
                for attr_name, attr_values in entry.items():
                    decoded_values = [v.decode('utf-8') for v in attr_values]
                    result_builder.append(f"  {attr_name}: {', '.join(decoded_values)}")

    except ldap.SERVER_DOWN:
        return f"Error: Could not connect to LDAP server at {ldap_uri}. Is it running?"
    except ldap.NO_SUCH_OBJECT:
        return f"Error: Base DN '{base_dn}' not found on the server."
    except ldap.LDAPError as e:
        return f"LDAP search error: {e}"
    finally:
        if conn:
            conn.unbind_s()
            
    return "\n".join(result_builder)


def main():
    """
    Main function to handle command-line arguments and run test cases.
    """
    # Note: This script requires the 'python-ldap' library.
    # Install with: pip install python-ldap
    # An LDAP server must be running on localhost:389 for this to work.
    if len(sys.argv) > 1:
        print("--- Running with provided argument ---")
        result = find_user_in_ldap(sys.argv[1])
        print(result)
    else:
        print("--- Running with pre-defined test cases ---")
        print("NOTE: These tests require a local LDAP server populated with sample data.")
        
        test_cases = [
            "jdoe@example.com",           # Normal valid user
            "admin@example.com",          # Another valid user
            "test.user@sub.example.com",  # User in a subdomain
            "*@example.com",              # Potential injection attempt, should be escaped
            "jdoe)(uid=*))(|(uid=*@example.com", # Advanced injection attempt
        ]
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n--- Test Case {i}: {test_case} ---")
            result = find_user_in_ldap(test_case)
            print(result)

if __name__ == "__main__":
    main()