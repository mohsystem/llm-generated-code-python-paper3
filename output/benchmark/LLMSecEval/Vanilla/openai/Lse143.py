# In-memory "database" and mailing list
users_db = {"alice@example.com", "bob@example.com", "carol@example.com"}
mailing_list = set(users_db)

def _normalize(email: str) -> str:
    return email.strip().lower()

# Simulates handling a GET /unsubscribe?email=<email>
def unsubscribe_get(email: str) -> str:
    if email is None or not email.strip():
        return "Invalid email parameter."
    norm = _normalize(email)
    if norm in users_db:
        users_db.remove(norm)       # delete user from the "database"
        mailing_list.discard(norm)  # unsubscribe from mailing list
        return f"{norm} has been unsubscribed."
    else:
        return f"{norm} is not subscribed."

if __name__ == "__main__":
    tests = [
        "alice@example.com",    # subscribed -> unsubscribe
        "dave@example.com",     # not subscribed
        "bob@example.com",      # subscribed -> unsubscribe
        "bob@example.com",      # already unsubscribed
        "Carol@Example.com"     # case-insensitive match -> unsubscribe
    ]
    for t in tests:
        print(unsubscribe_get(t))