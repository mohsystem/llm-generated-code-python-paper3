def is_valid_email(email: str) -> bool:
    if not isinstance(email, str):
        return False
    length = len(email)
    if length == 0 or length > 254:
        return False

    if email.count('@') != 1:
        return False

    local, domain = email.split('@', 1)
    if not local or not domain:
        return False
    if len(local) > 64:
        return False

    if local[0] == '.' or local[-1] == '.' or '..' in local:
        return False

    def is_alpha(c: str) -> bool:
        return ('A' <= c <= 'Z') or ('a' <= c <= 'z')

    def is_digit(c: str) -> bool:
        return '0' <= c <= '9'

    def is_local_allowed(c: str) -> bool:
        return is_alpha(c) or is_digit(c) or c in '._%+-'

    for ch in local:
        if not is_local_allowed(ch):
            return False

    if domain[0] == '.' or domain[-1] == '.' or '..' in domain:
        return False

    if '.' not in domain:
        return False

    def is_domain_label_char(c: str) -> bool:
        return ('A' <= c <= 'Z') or ('a' <= c <= 'z') or ('0' <= c <= '9') or c == '-'

    labels = domain.split('.')
    if len(labels) < 2:
        return False

    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if label[0] == '-' or label[-1] == '-':
            return False
        for ch in label:
            if not is_domain_label_char(ch):
                return False

    tld = labels[-1]
    if len(tld) < 2 or not all('A' <= c <= 'Z' or 'a' <= c <= 'z' for c in tld):
        return False

    return True


if __name__ == "__main__":
    tests = [
        "user.name+tag@example.com",
        "user@sub.example.co",
        "user..name@example.com",
        "user@-example.com",
        "user@example",
    ]
    for e in tests:
        print(f"{e} -> {is_valid_email(e)}")