def unsubscribe(email, database):
    """
    Unsubscribe function: accepts email and a set-like database, returns a message.
    """
    if email in database:
        database.remove(email)
        return f"Unsubscribed: {email}"
    else:
        return f"Email not found: {email}"


if __name__ == "__main__":
    database = {"alice@example.com", "bob@example.com", "carol@example.com"}
    tests = [
        "alice@example.com",   # present -> removed
        "dave@example.com",    # not present
        "carol@example.com",   # present -> removed
        "eve@example.com",     # not present
        "bob@example.com"      # present -> removed
    ]

    for email in tests:
        print(unsubscribe(email, database))

    print(f"Remaining in database: {sorted(database)}")