from typing import List

def is_valid_email(email: str) -> bool:
    if email is None:
        return False

    # Length checks
    n = len(email)
    if n < 3 or n > 254:
        return False

    # No leading/trailing whitespace and ASCII only printable (excluding space)
    if email != email.strip():
        return False
    for ch in email:
        if ord(ch) < 0x20 or ord(ch) >= 0x7F:
            return False

    # Single '@'
    try:
        at = email.index('@')
    except ValueError:
        return False
    if at == 0 or at == n - 1 or at != email.rfind('@'):
        return False

    local = email[:at]
    domain = email[at + 1:]

    # Local length
    if len(local) < 1 or len(local) > 64:
        return False

    # Local allowed chars and dot rules
    if local[0] == '.' or local[-1] == '.':
        return False
    prev_dot = False
    for ch in local:
        if not _is_allowed_local_char(ch):
            return False
        if ch == '.':
            if prev_dot:
                return False
            prev_dot = True
        else:
            prev_dot = False

    # Domain checks
    if len(domain) < 1 or len(domain) > 253:
        return False
    if domain[0] == '.' or domain[-1] == '.':
        return False

    has_dot = False
    label_len = 0
    current_label_alpha_only = True
    last_label_alpha_only = False
    prev = ''

    for ch in domain:
        if ch == '.':
            if label_len == 0:
                return False
            if prev == '-':
                return False
            has_dot = True
            last_label_alpha_only = current_label_alpha_only
            label_len = 0
            current_label_alpha_only = True
            prev = ch
            continue

        if not _is_allowed_domain_char(ch):
            return False

        if ch == '-':
            if label_len == 0:
                return False
            current_label_alpha_only = False
        elif ch.isdigit():
            current_label_alpha_only = False
        elif ch.isalpha():
            pass
        else:
            return False

        label_len += 1
        if label_len > 63:
            return False
        prev = ch

    if label_len == 0:
        return False
    if prev == '-':
        return False
    last_label_alpha_only = current_label_alpha_only

    if not has_dot:
        return False
    if not last_label_alpha_only or label_len < 2:
        return False

    return True


def _is_allowed_local_char(c: str) -> bool:
    if c.isalpha() or c.isdigit():
        return True
    return c in "!#$%&'*+/=?^_`{|}~.-"


def _is_allowed_domain_char(c: str) -> bool:
    return c.isalpha() or c.isdigit() or c in "-."


def main() -> None:
    tests: List[str] = [
        "alice@example.com",
        "john.doe+tag@sub.example.co.uk",
        ".startsWithDot@domain.com",
        "no_at_symbol.domain.com",
        "bad-domain@exa_mple.com",
    ]
    for t in tests:
        print(f"{t} => {is_valid_email(t)}")


if __name__ == "__main__":
    main()