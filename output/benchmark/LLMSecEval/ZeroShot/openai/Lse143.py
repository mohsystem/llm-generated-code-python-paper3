import re

EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')

def _normalize_email(email: str) -> str:
    return email.strip().lower() if email is not None else None

def _is_valid_email(email: str) -> bool:
    if email is None:
        return False
    if len(email) > 254:
        return False
    return EMAIL_RE.match(email) is not None

# Unsubscribe function: accepts input as parameters and returns output
def unsubscribe(email: str, database: set, mailing_list: set) -> str:
    normalized = _normalize_email(email)
    if not _is_valid_email(normalized):
        return "Invalid email address."
    if normalized in database:
        database.discard(normalized)       # delete user from database
        mailing_list.discard(normalized)   # unsubscribe from mailing list
        return "Successfully unsubscribed."
    else:
        return "Email not subscribed."

if __name__ == "__main__":
    database = {
        "alice@example.com",
        "bob@example.org",
        "upper@example.com",
        "carol+news@sub.example.co",
        "dave@example.net"
    }
    mailing_list = {
        "alice@example.com",
        "bob@example.org",
        "upper@example.com",
        "carol+news@sub.example.co"
    }

    # 5 test cases
    print(unsubscribe("Alice@Example.com", database, mailing_list))    # success
    print(unsubscribe("unknown@example.com", database, mailing_list))  # not subscribed
    print(unsubscribe("invalid-email", database, mailing_list))        # invalid
    print(unsubscribe("BOB@EXAMPLE.ORG", database, mailing_list))      # success
    print(unsubscribe("dave@example.net", database, mailing_list))     # success