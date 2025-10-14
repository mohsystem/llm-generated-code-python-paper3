import ldap3
from ldap3.utils.conv import escape_filter_chars

def search_ldap_user(dc_string, username):
    """
    Searches for a user in an LDAP directory.

    NOTE: Requires the 'ldap3' library. Install with: pip install ldap3

    :param dc_string: A comma-separated string of domain components (e.g., "example,com").
    :param username: The username to search for.
    :return: A string containing user information or an error/not found message.
    """
    server_uri = 'ldap://localhost:389'
    result_builder = []
    conn = None

    try:
        server = ldap3.Server(server_uri, get_info=ldap3.ALL)
        # For simplicity, using anonymous bind. In a real application, provide user and password.
        conn = ldap3.Connection(server, auto_bind=True)

        search_base = "dc=" + dc_string.replace(',', ',dc=')
        
        # Securely construct the search filter by escaping the username
        escaped_username = escape_filter_chars(username)
        search_filter = f'(cn={escaped_username})'

        result_builder.append(f"Searching for user '{username}'")
        result_builder.append(f"Base DN: {search_base}")
        result_builder.append(f"Filter: {search_filter}\n")

        conn.search(search_base, search_filter, attributes=ldap3.ALL_ATTRIBUTES)

        if conn.entries:
            for entry in conn.entries:
                result_builder.append(f"Found user: {entry.entry_dn}")
                result_builder.append(str(entry.entry_to_json(indent=2)))
        else:
            result_builder.append(f"User '{username}' not found.")

    except ldap3.core.exceptions.LDAPSocketOpenError as e:
        return f"Could not connect to LDAP server at {server_uri}: {e}"
    except ldap3.core.exceptions.LDAPBindError as e:
        return f"LDAP Bind Error: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"
    finally:
        if conn and conn.bound:
            conn.unbind()
            
    return "\n".join(result_builder)


def main():
    print("NOTE: This program requires the 'ldap3' library (pip install ldap3).")
    print("NOTE: This program also requires an LDAP server running on localhost:389.")
    print("For tests to succeed, it should have a base DN like 'dc=example,dc=com'")
    print("and users with cn='jdoe', 'test(user)', 'star*user', etc.\n")

    test_cases = [
        ("jdoe", "example,com"),        # 1. Normal valid user
        ("nonexistent", "example,com"), # 2. User not found
        ("test(user)", "example,com"),  # 3. Username with parentheses
        ("star*user", "example,com"),   # 4. Username with asterisk
        ("*", "example,com")            # 5. Potential injection attempt
    ]

    for i, (username, dc_string) in enumerate(test_cases, 1):
        print(f"----------- Test Case {i} -----------")
        result = search_ldap_user(dc_string, username)
        print(result)
        print()

if __name__ == '__main__':
    main()