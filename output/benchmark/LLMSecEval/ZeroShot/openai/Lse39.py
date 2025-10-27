import hmac

class Lse39:
    # In-memory user store with expected password bytes (for demo purposes)
    USER_STORE = {
        "alice": b"Str0ngP@ss!",
        "admin": b"S3cure#Admin",
    }
    # Dummy secret to mitigate user enumeration/timing side-channel
    DUMMY_SECRET = b"Dummy#Secret1"

    @staticmethod
    def secure_equals(a: bytes, b: bytes) -> bool:
        return hmac.compare_digest(a, b)

    @staticmethod
    def login(username: str, password: str) -> str:
        if not username or password is None:
            return "Invalid username or password."
        expected = Lse39.USER_STORE.get(username, Lse39.DUMMY_SECRET)
        ok = Lse39.secure_equals(password.encode("utf-8"), expected)
        if ok and username in Lse39.USER_STORE:
            return f"SESSION: {username}"
        return "Invalid username or password."

if __name__ == "__main__":
    # 5 test cases
    print(Lse39.login("alice", "Str0ngP@ss!"))
    print(Lse39.login("alice", "wrong"))
    print(Lse39.login("admin", "S3cure#Admin"))
    print(Lse39.login("eve", "anything"))
    print(Lse39.login("", "S3cure#Admin"))