import hmac

STORED_USER = "admin"
STORED_PASS = "S3cureP@ss!"

def _to_bytes(s):
    if s is None:
        return b""
    if isinstance(s, bytes):
        return s
    return str(s).encode("utf-8", "strict")

def check_mod(username, password):
    u_ok = hmac.compare_digest(_to_bytes(username), _to_bytes(STORED_USER))
    p_ok = hmac.compare_digest(_to_bytes(password), _to_bytes(STORED_PASS))
    return "true" if (u_ok and p_ok) else "false"

if __name__ == "__main__":
    # 5 test cases
    print(check_mod("admin", "S3cureP@ss!"))  # expected true
    print(check_mod("admin", "wrong"))        # expected false
    print(check_mod("user", "S3cureP@ss!"))   # expected false
    print(check_mod("", ""))                  # expected false
    print(check_mod("admin", "S3cureP@ss!!")) # expected false