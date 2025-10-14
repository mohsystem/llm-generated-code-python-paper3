import re
import sys
from typing import Optional

try:
    import ldap
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

MAX_INPUT_LENGTH = 256
DC_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$')
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
LDAP_URL = "ldap://localhost:389"


def sanitize_ldap_filter(value: str) -> str:
    """Sanitize input for LDAP filter to prevent injection."""
    escape_map = {
        '\\': r'\5c',
        '*': r'\2a',
        '(': r'\28',
        ')': r'\29',
        '\x00': r'\00'
    }
    result = value
    for char, escaped in escape_map.items():
        result = result.replace(char, escaped)
    return result


def search_user(dc_input: Optional[str], username: Optional[str]) -> str:
    """Search for a user in LDAP directory."""
    if not LDAP_AVAILABLE:
        return "Error: python-ldap module not available"

    if dc_input is None or username is None:
        return "Error: Input cannot be null"

    if len(dc_input) > MAX_INPUT_LENGTH or len(username) > MAX_INPUT_LENGTH:
        return "Error: Input exceeds maximum length"

    if not dc_input or not username:
        return "Error: Input cannot be empty"

    if not USERNAME_PATTERN.match(username):
        return "Error: Invalid username format"

    dc_components = dc_input.split('.')
    if not dc_components or len(dc_components) > 10:
        return "Error: Invalid domain component format"

    for dc in dc_components:
        if not DC_PATTERN.match(dc):
            return f"Error: Invalid domain component: {dc}"

    base_dn = ','.join([f"dc={dc}" for dc in dc_components])
    sanitized_username = sanitize_ldap_filter(username)
    ldap_filter = f"(uid={sanitized_username})"

    conn = None
    try:
        conn = ldap.initialize(LDAP_URL)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5.0)
        conn.set_option(ldap.OPT_TIMEOUT, 5.0)
        conn.set_option(ldap.OPT_REFERRALS, 0)

        conn.simple_bind_s()

        results = conn.search_s(
            base_dn,
            ldap.SCOPE_SUBTREE,
            ldap_filter,
            ['uid', 'cn', 'mail'],
            sizelimit=10
        )

        if not results:
            return "No user found"

        output = []
        for dn, attrs in results[:10]:
            output.append(f"DN: {dn}")
            for attr_name, attr_values in attrs.items():
                for value in attr_values:
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='replace')
                    output.append(f"{attr_name}: {value}")
            output.append("---")

        return '\n'.join(output[:-1])

    except ldap.LDAPError as e:
        return f"Error: LDAP operation failed - {type(e).__name__}"
    finally:
        if conn is not None:
            try:
                conn.unbind_s()
            except Exception:
                pass


def main() -> None:
    """Main function with test cases."""
    print("Test 1: Valid input")
    print(search_user("example.com", "testuser"))
    print()

    print("Test 2: Invalid username with special chars")
    print(search_user("example.com", "test*user"))
    print()

    print("Test 3: Null input")
    print(search_user(None, "testuser"))
    print()

    print("Test 4: Empty input")
    print(search_user("", "testuser"))
    print()

    print("Test 5: Invalid domain component")
    print(search_user("exam ple.com", "testuser"))


if __name__ == "__main__":
    main()
