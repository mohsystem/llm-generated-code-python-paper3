# Chain-of-Through secure implementation for email validation in Python

def validate_email(email: str) -> bool:
    if email is None:
        return False
    if not isinstance(email, str):
        return False
    length = len(email)
    if length == 0 or length > 254:
        return False

    # Reject non-ASCII and whitespace/control
    for ch in email:
        oc = ord(ch)
        if oc <= 32 or oc >= 127:
            return False

    try:
        at_first = email.index('@')
        at_last = email.rindex('@')
    except ValueError:
        return False
    if at_first <= 0 or at_first != at_last or at_first == length - 1:
        return False

    local = email[:at_first]
    domain = email[at_first + 1:]

    # Validate local
    if len(local) == 0 or len(local) > 64:
        return False
    if local[0] == '.' or local[-1] == '.':
        return False

    prev_dot = False
    for c in local:
        if not (is_alnum_ascii(c) or c in '._+-'):
            return False
        if c == '.':
            if prev_dot:
                return False
            prev_dot = True
        else:
            prev_dot = False

    # Validate domain
    if len(domain) == 0 or len(domain) > 253:
        return False
    labels = domain.split('.')
    if '' in labels:
        return False  # catches consecutive dots and empty labels
    if len(labels) < 2:
        return False
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if not is_alnum_ascii(label[0]) or not is_alnum_ascii(label[-1]):
            return False
        for c in label:
            if not (is_alnum_ascii(c) or c == '-'):
                return False

    tld = labels[-1]
    if len(tld) < 2 or len(tld) > 63:
        return False
    if not all(is_alpha_ascii(c) for c in tld):
        return False

    return True

def is_alnum_ascii(c: str) -> bool:
    return ('A' <= c <= 'Z') or ('a' <= c <= 'z') or ('0' <= c <= '9')

def is_alpha_ascii(c: str) -> bool:
    return ('A' <= c <= 'Z') or ('a' <= c <= 'z')


if __name__ == "__main__":
    # 5 test cases
    tests = [
        "user.name+tag-123@example-domain.com",  # valid
        "a_b@example.co",                        # valid
        "user..dot@example.com",                 # invalid
        "user@example",                          # invalid
        ".startingdot@example.com",              # invalid
    ]
    for t in tests:
        print(f"{t} -> {validate_email(t)}")