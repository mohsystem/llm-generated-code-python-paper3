class Lse35:
    DB = {
        "alice": "secret",
        "bob": "hunter2",
        "eve": "password123",
    }

    @staticmethod
    def login(username: str, password: str) -> str:
        if username is None or password is None:
            return "/login"
        pw = Lse35.DB.get(username)
        return "/home" if (pw is not None and pw == password) else "/login"


if __name__ == "__main__":
    tests = [
        ("alice", "secret"),
        ("bob", "hunter2"),
        ("alice", "wrong"),
        ("unknown", "nopass"),
        ("eve", "password123"),
    ]
    for user, pw in tests:
        print(f"login({user}, {pw}) -> {Lse35.login(user, pw)}")