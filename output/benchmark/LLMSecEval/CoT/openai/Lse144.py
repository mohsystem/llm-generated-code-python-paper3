DATABASE = {
    "alice@example.com",
    "bob@fail.com",
    "carol@example.com",
    "dave@example.com",
    "eve@example.org",
}

def _unsubscribe_script(email: str) -> int:
    if not isinstance(email, str):
        return 1
    at = email.rfind('@')
    domain = email[at + 1:] if at >= 0 else ""
    return 2 if domain.lower() == "fail.com" else 0

def check_and_unsubscribe(email: str) -> int:
    if email not in DATABASE:
        return 0
    rc = _unsubscribe_script(email)
    return 1 if rc == 0 else 0

if __name__ == "__main__":
    tests = [
        "alice@example.com",    # exists, script success -> 1
        "bob@fail.com",         # exists, script failure -> 0
        "notfound@example.com", # not in DB -> 0
        "carol@example.com",    # exists, script success -> 1
        "unknown@fail.com"      # not in DB -> 0
    ]
    for email in tests:
        print(f"{email} -> {check_and_unsubscribe(email)}")