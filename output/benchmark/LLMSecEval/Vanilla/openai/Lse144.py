# Simulated database
DATABASE = {
    "alice@example.com",
    "bob_fail@example.com",
    "charlie@example.com",
}

# Simulated external script: returns 0 on success, non-zero on failure
def _call_unsubscribe_script(email: str) -> int:
    if not email:
        return 1  # failure
    if "fail" in email:
        return 2  # simulate failure
    return 0  # success

# Returns 1 if email exists and unsubscribe script succeeds (returns 0), else 0
def unsubscribeIfExists(email: str) -> int:
    if email is None:
        return 0
    if email not in DATABASE:
        return 0
    return 1 if _call_unsubscribe_script(email) == 0 else 0

if __name__ == "__main__":
    tests = [
        "alice@example.com",     # 1
        "missing@example.com",   # 0
        "bob_fail@example.com",  # 0
        "",                      # 0
        "charlie@example.com",   # 1
    ]
    for t in tests:
        print(unsubscribeIfExists(t))