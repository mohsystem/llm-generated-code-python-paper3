import hmac

class Lse37:
    _DB = {
        "alice": "StrongPass!42",
        "bob": "s3cr3t",
        "charlie": "passw0rd",
        "diana": "Qwerty!234",
    }
    _DUMMY_SECRET = "dummy_password_for_timing"
    _MAX_USERNAME_LEN = 64
    _MAX_PASSWORD_LEN = 128

    @staticmethod
    def handle_login(username: str, password: str) -> str:
        try:
            if username is None or password is None:
                return "cant_login"
            if username == "__simulate_error__":
                raise RuntimeError("Simulated internal error")
            if len(username) == 0 or len(username) > Lse37._MAX_USERNAME_LEN or len(password) > Lse37._MAX_PASSWORD_LEN:
                return "cant_login"

            stored = Lse37._DB.get(username)
            if stored is None:
                # Mitigate user enumeration
                hmac.compare_digest(password, Lse37._DUMMY_SECRET)
                return "cant_login"
            ok = hmac.compare_digest(password, stored)
            return "success" if ok else "cant_login"
        except Exception:
            return "internal_server_error"

if __name__ == "__main__":
    # 5 test cases
    print(Lse37.handle_login("alice", "StrongPass!42"))  # success
    print(Lse37.handle_login("alice", "wrong"))          # cant_login
    print(Lse37.handle_login("unknown", "whatever"))     # cant_login
    print(Lse37.handle_login("", "somepass"))            # cant_login
    print(Lse37.handle_login("__simulate_error__", "x")) # internal_server_error