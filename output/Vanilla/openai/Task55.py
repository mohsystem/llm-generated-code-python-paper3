def is_valid_email(email: str) -> bool:
    if email is None:
        return False
    if len(email) == 0 or len(email) > 254:
        return False
    if email.count('@') != 1:
        return False

    local, domain = email.split('@', 1)
    if len(local) == 0 or len(local) > 64:
        return False

    # Local part checks
    if local[0] == '.' or local[-1] == '.':
        return False
    prev = ''
    for c in local:
        if not (c.isalnum() or c in ['.', '_', '%', '+', '-']):
            return False
        if c == '.' and prev == '.':
            return False
        prev = c

    # Domain checks
    if len(domain) == 0:
        return False
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if not (label[0].isalnum() and label[-1].isalnum()):
            return False
        for ch in label:
            if not (ch.isalnum() or ch == '-'):
                return False
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False
    return True


if __name__ == "__main__":
    tests = [
        "user@example.com",
        "first.last+tag@sub.domain.co",
        ".user@domain.com",
        "user@-domain.com",
        "user@domain",
    ]
    for e in tests:
        print(f"{e} => {is_valid_email(e)}")