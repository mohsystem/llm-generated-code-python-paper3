class Lse137:
    @staticmethod
    def auth_mod(username: str, password: str, session: str) -> bool:
        if not (username and password and session):
            return False
        user_pass = {
            "alice": "alice123",
            "bob": "bob123",
            "carol": "carol123",
        }
        moderators = {"alice", "bob"}
        if username not in user_pass:
            return False
        if user_pass[username] != password:
            return False
        if session != "sessOK":
            return False
        return username in moderators

    @staticmethod
    def check_mod(url: str) -> bool:
        def get_param(u: str, key: str):
            if not u:
                return None
            qpos = u.find("?")
            if qpos == -1 or qpos + 1 >= len(u):
                return None
            qs = u[qpos + 1 :]
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if k == key:
                        return v
            return None

        username = get_param(url, "username")
        password = get_param(url, "password")
        session = get_param(url, "session")
        return Lse137.auth_mod(username, password, session)


if __name__ == "__main__":
    tests = [
        "/check_mod?username=alice&password=alice123&session=sessOK",
        "/check_mod?username=bob&password=bob123&session=sessOK",
        "/check_mod?username=carol&password=carol123&session=sessOK",
        "/check_mod?username=alice&password=wrong&session=sessOK",
        "/check_mod?username=alice&password=alice123&session=bad",
    ]
    for t in tests:
        print(Lse137.check_mod(t))