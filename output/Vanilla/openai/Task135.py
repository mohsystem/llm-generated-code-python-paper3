import secrets
import hmac

_tokens = {}

def issue_token(session_id: str) -> str:
    token = secrets.token_urlsafe(32)
    _tokens[session_id] = token
    return token

def validate_token(session_id: str, token: str) -> bool:
    expected = _tokens.get(session_id)
    if expected is None or token is None:
        return False
    return hmac.compare_digest(expected, token)

def rotate_token(session_id: str) -> str:
    return issue_token(session_id)

def invalidate_session(session_id: str) -> None:
    _tokens.pop(session_id, None)

if __name__ == "__main__":
    # 5 test cases
    s1 = "sessionA"
    s2 = "sessionB"

    t1 = issue_token(s1)
    print("Test1 (valid token):", validate_token(s1, t1))

    print("Test2 (invalid token):", validate_token(s1, "invalidtoken"))

    print("Test3 (missing session):", validate_token("noSession", t1))

    t2 = issue_token(s2)
    print("Test4 (cross-session misuse):", validate_token(s2, t1))

    old = t1
    rotated = rotate_token(s1)
    old_valid = validate_token(s1, old)
    new_valid = validate_token(s1, rotated)
    print("Test5 (rotate old invalid/new valid):", (not old_valid) and new_valid)