import os
import hmac
import hashlib
import secrets

class Task7:
    @staticmethod
    def build_login_request(username: str, password: str) -> str:
        if username is None or password is None:
            return ""
        if len(username) > 128 or len(password) > 256:
            return ""
        return f"op=login;user={Task7._escape(username)};pass={Task7._escape(password)}"

    @staticmethod
    def process_request(user_store_path: str, request: str) -> str:
        if request is None or len(request) > 4096:
            return "ERR:invalid request size"
        kv = Task7._parse_kv(request)
        if kv.get("op") != "login":
            return "ERR:unsupported op"
        user = kv.get("user")
        passwd = kv.get("pass")
        if user is None or passwd is None:
            return "ERR:missing fields"
        user = Task7._unescape(user)
        passwd = Task7._unescape(passwd)
        if not Task7._is_valid_username(user):
            return "ERR:invalid username"
        try:
            if Task7._authenticate(user_store_path, user, passwd):
                return f"OK:Welcome {user}"
            else:
                return "ERR:authentication failed"
        except Exception:
            return "ERR:server io error"

    @staticmethod
    def create_or_update_user(user_store_path: str, username: str, password: str) -> bool:
        if not Task7._is_valid_username(username):
            return False
        iterations = 10000
        salt = secrets.token_bytes(16)
        salt_hex = salt.hex()
        pwd_hash = Task7._hash_password(password, salt, iterations)
        records = {}
        if os.path.exists(user_store_path):
            try:
                with open(user_store_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.rstrip("\n")
                        if not line:
                            continue
                        parts = line.split(":")
                        if len(parts) != 4:
                            continue
                        records[parts[0]] = line
            except Exception:
                pass
        records[username] = f"{username}:{salt_hex}:{iterations}:{pwd_hash}"
        tmp_path = user_store_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                for k in records:
                    f.write(records[k] + "\n")
            os.replace(tmp_path, user_store_path)
        except Exception:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            return False
        return True

    @staticmethod
    def _authenticate(user_store_path: str, username: str, password: str) -> bool:
        if not os.path.exists(user_store_path):
            return False
        with open(user_store_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) != 4:
                    continue
                u, salt_hex, iter_str, stored_hash = parts
                if u != username:
                    continue
                try:
                    iters = int(iter_str)
                except ValueError:
                    return False
                if iters < 1000 or iters > 200000:
                    return False
                try:
                    salt = bytes.fromhex(salt_hex)
                except ValueError:
                    return False
                computed = Task7._hash_password(password, salt, iters)
                return hmac.compare_digest(stored_hash.encode("ascii"), computed.encode("ascii"))
        return False

    @staticmethod
    def _hash_password(password: str, salt: bytes, iterations: int) -> str:
        h = hashlib.sha256(salt + password.encode("utf-8")).digest()
        for _ in range(iterations):
            h = hashlib.sha256(h + salt).digest()
        return h.hex()

    @staticmethod
    def _is_valid_username(u: str) -> bool:
        if not u or len(u) > 64:
            return False
        for ch in u:
            if not (ch.isalnum() or ch in "_.-"):
                return False
        return True

    @staticmethod
    def _escape(s: str) -> str:
        out = []
        for ch in s:
            if ch in ['\\', ';', '=']:
                out.append('\\')
            out.append(ch)
        return "".join(out)

    @staticmethod
    def _unescape(s: str) -> str:
        out = []
        esc = False
        for ch in s:
            if esc:
                out.append(ch)
                esc = False
            else:
                if ch == '\\':
                    esc = True
                else:
                    out.append(ch)
        return "".join(out)

    @staticmethod
    def _parse_kv(s: str) -> dict:
        m = {}
        key = []
        val = []
        in_key = True
        esc = False
        for ch in s:
            if esc:
                (key if in_key else val).append(ch)
                esc = False
            else:
                if ch == '\\':
                    esc = True
                elif ch == '=' and in_key:
                    in_key = False
                elif ch == ';':
                    if key:
                        m["".join(key)] = "".join(val)
                    key = []
                    val = []
                    in_key = True
                else:
                    (key if in_key else val).append(ch)
        if key:
            m["".join(key)] = "".join(val)
        return m

if __name__ == "__main__":
    store = "users_py.db"
    Task7.create_or_update_user(store, "alice", "Wonder@123")
    Task7.create_or_update_user(store, "bob", "Builder#456")

    reqs = [
        Task7.build_login_request("alice", "Wonder@123"),
        Task7.build_login_request("alice", "wrongpass"),
        Task7.build_login_request("charlie", "Anything1!"),
        Task7.build_login_request("bob", "Builder#456"),
        Task7.build_login_request("bad;user", "str@nge=pass"),
    ]

    for i, r in enumerate(reqs, 1):
        print(f"Case {i}: {Task7.process_request(store, r)}")