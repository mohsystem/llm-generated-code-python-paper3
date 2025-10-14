import sys
import re
from typing import Dict

def sanitize_ldap_input(input_str: str) -> str:
    """Sanitize input to prevent LDAP injection attacks"""
    if not input_str:
        return ""

    # Escape LDAP special characters
    escape_map = {
        '\\': r'\5c',
        '*': r'\2a',
        '(': r'\28',
        ')': r'\29',
        '\x00': r'\00',
    }

    result = []
    for char in input_str:
        result.append(escape_map.get(char, char))

    return ''.join(result)


def sanitize_dn(input_str: str) -> str:
    """Sanitize DN components"""
    if not input_str:
        return ""

    result = []
    special_chars = ['\\', ',', '+', '"', '<', '>', ';', '=']

    for i, char in enumerate(input_str):
        if char in special_chars:
            result.append('\\' + char)
        elif char == '#' and i == 0:
            result.append('\\' + char)
        elif char == ' ' and (i == 0 or i == len(input_str) - 1):
            result.append('\\' + char)
        else:
            result.append(char)

    return ''.join(result)


def search_user(username: str, dc: str) -> Dict[str, str]:
    """Search for user in LDAP server"""
    user_info: Dict[str, str] = {}

    # Validate inputs
    if not username or not username.strip():
        user_info['error'] = "Username cannot be empty"
        return user_info

    if not dc or not dc.strip():
        user_info['error'] = "Domain component cannot be empty"
        return user_info

    # Sanitize inputs
    sanitized_username = sanitize_ldap_input(username.strip())
    sanitized_dc = sanitize_dn(dc.strip())

    # Validate DC format
    if not re.match(r'^[a-zA-Z0-9\-,]+$', sanitized_dc):
        user_info['error'] = "Invalid domain component format"
        return user_info

    try:
        import ldap

        # Initialize LDAP connection
        ldap_server = "ldap://localhost:389"
        conn = ldap.initialize(ldap_server)

        # Set connection options for security
        conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5.0)

        # Construct base DN
        dc_parts = sanitized_dc.split(',')
        base_dn = ','.join([f"dc={part.strip()}" for part in dc_parts])

        # Create search filter with sanitized input
        search_filter = f"(uid={sanitized_username})"

        # Perform search with limits
        results = conn.search_s(
            base_dn,
            ldap.SCOPE_SUBTREE,
            search_filter,
            None
        )

        if results:
            dn, attributes = results[0]
            user_info['dn'] = dn

            # Extract attributes safely
            for key, value in attributes.items():
                if value:
                    user_info[key] = value[0].decode('utf-8') if isinstance(value[0], bytes) else str(value[0])

            user_info['status'] = "User found"
        else:
            user_info['status'] = "User not found"

        conn.unbind_s()

    except ImportError:
        user_info['error'] = "python-ldap module not installed. Install with: pip install python-ldap"
    except Exception as e:
        user_info['error'] = f"LDAP error: {str(e)}"

    return user_info


def print_result(result: Dict[str, str]):
    """Print search results"""
    print("Result:")
    for key, value in result.items():
        print(f"  {key}: {value}")


def main():
    print("=== LDAP User Search Program ===\n")

    # Test cases
    test_cases = [
        ("jdoe", "example,com"),
        ("alice", "test,org"),
        ("bob123", "company,local"),
        ("user*", "example,com"),  # Test injection attempt
        ("admin", "corp,internal")
    ]

    if len(sys.argv) >= 3:
        # Use command line arguments
        username = sys.argv[1]
        dc = sys.argv[2]
        print(f"Searching for user: {username} in domain: {dc}")
        result = search_user(username, dc)
        print_result(result)
    else:
        # Run test cases
        print("No command line arguments provided. Running test cases...\n")

        for i, (username, dc) in enumerate(test_cases, 1):
            print(f"Test Case {i}:")
            print(f"Username: {username}")
            print(f"DC: {dc}")

            result = search_user(username, dc)
            print_result(result)
            print("-----------------------------------\n")


if __name__ == "__main__":
    main()
