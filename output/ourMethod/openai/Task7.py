import os
import socket
import threading
import base64
import hmac
import json
from typing import Dict, Tuple
from pathlib import Path
from secrets import token_bytes
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ENC1"
VERSION = 1
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
PBKDF2_ITER = 210_000
AES_KEY_LEN = 32

USERNAME_ALLOWED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def is_valid_username(u: str) -> bool:
    if not (3 <= len(u) <= 32): return False
    return all(ch in USERNAME_ALLOWED for ch in u)


def pbkdf2(pass_bytes: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
    return kdf.derive(pass_bytes)


def aesgcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.encrypt(iv, plaintext, None)  # returns ciphertext||tag


def aesgcm_decrypt(key: bytes, iv: bytes, ciphertext_and_tag: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(iv, ciphertext_and_tag, None)


def secure_base_dir(base: Path) -> Path:
    p = base.resolve()
    p.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        raise RuntimeError("base dir is symlink")
    return p


def secure_resolve(base: Path, name: str) -> Path:
    if not all(ch in USERNAME_ALLOWED or ch == '.' for ch in name):
        raise RuntimeError("invalid file name")
    p = (base / name).resolve()
    if base not in p.parents and p != base / name:
        raise RuntimeError("path traversal")
    return p


@dataclass
class UserRecord:
    salt: bytes
    hash: bytes


class UserStore:
    def __init__(self, base_dir: Path, enc_pass: bytes):
        self.base_dir = secure_base_dir(base_dir)
        self.db_file = secure_resolve(self.base_dir, "users.enc")
        self.enc_pass = bytes(enc_pass)
        self._lock = threading.Lock()

    def _read_all(self) -> Dict[str, UserRecord]:
        with self._lock:
            if not self.db_file.exists():
                return {}
            data = self.db_file.read_bytes()
            if len(data) < 4 + 4 + SALT_LEN + IV_LEN + TAG_LEN:
                raise RuntimeError("truncated")
            pos = 0
            if data[pos:pos+4] != MAGIC:
                raise RuntimeError("bad magic")
            pos += 4
            ver = int.from_bytes(data[pos:pos+4], 'big')
            pos += 4
            if ver != VERSION:
                raise RuntimeError("bad version")
            salt = data[pos:pos+SALT_LEN]; pos += SALT_LEN
            iv = data[pos:pos+IV_LEN]; pos += IV_LEN
            ct_and_tag = data[pos:]
            key = pbkdf2(self.enc_pass, salt, PBKDF2_ITER, AES_KEY_LEN)
            plaintext = aesgcm_decrypt(key, iv, ct_and_tag)
            content = plaintext.decode('utf-8')
            return self._parse_users(content)

    def _write_all(self, m: Dict[str, UserRecord]):
        with self._lock:
            content = self._serialize_users(m).encode("utf-8")
            salt = token_bytes(SALT_LEN)
            iv = token_bytes(IV_LEN)
            key = pbkdf2(self.enc_pass, salt, PBKDF2_ITER, AES_KEY_LEN)
            ct_and_tag = aesgcm_encrypt(key, iv, content)
            out = MAGIC + VERSION.to_bytes(4, 'big') + salt + iv + ct_and_tag
            tmp = self.db_file.with_suffix(".tmp." + base64.urlsafe_b64encode(token_bytes(6)).decode('ascii'))
            tmp.write_bytes(out)
            os.replace(tmp, self.db_file)

    @staticmethod
    def _parse_users(s: str) -> Dict[str, UserRecord]:
        m: Dict[str, UserRecord] = {}
        if not s:
            return m
        for line in s.splitlines():
            if not line.strip():
                continue
            parts = line.split(":")
            if len(parts) != 3:
                raise RuntimeError("bad line")
            user = parts[0]
            if not is_valid_username(user):
                raise RuntimeError("bad username")
            salt = base64.b64decode(parts[1])
            h = base64.b64decode(parts[2])
            m[user] = UserRecord(salt=salt, hash=h)
        return m

    @staticmethod
    def _serialize_users(m: Dict[str, UserRecord]) -> str:
        lines = []
        for u, rec in m.items():
            lines.append(f"{u}:{base64.b64encode(rec.salt).decode()}:{base64.b64encode(rec.hash).decode()}")
        return "\n".join(lines)

    def add_user(self, username: str, password: str) -> bool:
        if not is_valid_username(username):
            return False
        if not self._is_strong_password(password):
            return False
        all_users = self._read_all()
        if username in all_users:
            return False
        salt = token_bytes(SALT_LEN)
        h = pbkdf2(password.encode("utf-8"), salt, PBKDF2_ITER, 32)
        all_users[username] = UserRecord(salt=salt, hash=h)
        self._write_all(all_users)
        return True

    def verify_login(self, username: str, password: str) -> bool:
        if not is_valid_username(username):
            return False
        all_users = self._read_all()
        rec = all_users.get(username)
        if not rec:
            return False
        calc = pbkdf2(password.encode("utf-8"), rec.salt, PBKDF2_ITER, len(rec.hash))
        return hmac.compare_digest(calc, rec.hash)

    @staticmethod
    def _is_strong_password(pw: str) -> bool:
        if len(pw) < 12:
            return False
        hasU = any(c.isupper() for c in pw)
        hasL = any(c.islower() for c in pw)
        hasD = any(c.isdigit() for c in pw)
        hasS = any(not c.isalnum() for c in pw)
        return hasU and hasL and hasD and hasS


def send_framed(sock: socket.socket, data: Dict[str, str]):
    blob = "&".join([f"{k}={quote(v)}" for k, v in data.items()]).encode("utf-8")
    sock.sendall(len(blob).to_bytes(4, 'big') + blob)


def recv_framed(sock: socket.socket) -> Dict[str, str] | None:
    hdr = recvn(sock, 4)
    if hdr is None:
        return None
    ln = int.from_bytes(hdr, 'big')
    if ln < 0 or ln > 1_048_576:
        raise RuntimeError("bad frame len")
    body = recvn(sock, ln)
    if body is None:
        return None
    return parse_kv(body.decode("utf-8"))


def recvn(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def quote(s: str) -> str:
    return json.dumps(s)[1:-1]  # simple escape


def unquote(s: str) -> str:
    return json.loads('"' + s + '"')


def parse_kv(s: str) -> Dict[str, str]:
    m: Dict[str, str] = {}
    if not s:
        return m
    for part in s.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            m[k] = unquote(v)
    return m


class Server(threading.Thread):
    def __init__(self, host: str, port: int, store: UserStore, max_clients: int):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.store = store
        self.max_clients = max_clients
        self.running = True
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_pub = self.rsa_priv.public_key()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            handled = 0
            while self.running and handled < self.max_clients:
                try:
                    c, addr = s.accept()
                except OSError:
                    break
                handled += 1
                threading.Thread(target=self.handle_client, args=(c,), daemon=True).start()

    def handle_client(self, c: socket.socket):
        with c:
            # Send public key
            pk_der = self.rsa_pub.public_bytes(encoding=serialization.Encoding.DER,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
            hello = {"op": "pubkey", "algo": "rsa-oaep-sha256", "host": "localhost",
                     "pk_der_b64": base64.b64encode(pk_der).decode()}
            send_framed(c, hello)

            req = recv_framed(c)
            if not req:
                return
            resp = {"op": "login_result"}
            if req.get("op") != "login":
                resp.update({"status": "error", "msg": "unsupported op"})
                send_framed(c, resp)
                return
            username = req.get("username", "")
            try:
                enc = base64.b64decode(req.get("pwdenc_b64", ""), validate=True)
                pwd = self.rsa_priv.decrypt(enc, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(), label=None)).decode("utf-8")
            except Exception:
                resp.update({"status": "error", "msg": "decryption failed"})
                send_framed(c, resp)
                return
            try:
                ok = self.store.verify_login(username, pwd)
            except Exception:
                resp.update({"status": "error", "msg": "auth error"})
                send_framed(c, resp)
                return
            if ok:
                resp.update({"status": "ok", "msg": "welcome"})
            else:
                resp.update({"status": "error", "msg": "invalid credentials"})
            send_framed(c, resp)

    def stop(self):
        self.running = False
        try:
            with socket.create_connection((self.host, self.port), timeout=1):
                pass
        except Exception:
            pass


class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def login(self, username: str, password: str) -> str:
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            hello = recv_framed(s)
            if not hello or hello.get("op") != "pubkey" or hello.get("algo") != "rsa-oaep-sha256" or hello.get("host") != "localhost":
                return "error:bad-hello"
            pk_der = base64.b64decode(hello.get("pk_der_b64", ""))
            pub = serialization.load_der_public_key(pk_der)
            enc = pub.encrypt(password.encode("utf-8"),
                              padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                           algorithm=hashes.SHA256(), label=None))
            req = {"op": "login", "username": username, "pwdenc_b64": base64.b64encode(enc).decode()}
            send_framed(s, req)
            resp = recv_framed(s)
            if not resp or resp.get("op") != "login_result":
                return "error:no-resp"
            return f"{resp.get('status','error')}:{resp.get('msg','')}"


def gen_strong_password() -> str:
    import string, secrets
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}:,.?/|~"
    pool = upper + lower + digits + special
    pw = [secrets.choice(upper), secrets.choice(lower), secrets.choice(digits), secrets.choice(special)]
    for _ in range(12):
        pw.append(secrets.choice(pool))
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def main():
    base = Path("data_py")
    enc_pass = os.environ.get("USERS_PASSPHRASE")
    if enc_pass is None or len(enc_pass) < 16:
        enc_pass = base64.b64encode(token_bytes(24)).decode()
    store = UserStore(base, enc_pass.encode("utf-8"))

    user1, user2 = "alice", "bob"
    pwd1, pwd2 = gen_strong_password(), gen_strong_password()
    store.add_user(user1, pwd1)
    store.add_user(user2, pwd2)

    srv = Server("127.0.0.1", 55556, store, max_clients=5)
    srv.start()
    # Give server time to start
    threading.Event().wait(0.2)

    cli = Client("127.0.0.1", 55556)

    # 5 tests
    print("Test1:", cli.login(user1, pwd1))          # expected ok
    print("Test2:", cli.login(user1, "WrongPass1!")) # expected error
    print("Test3:", cli.login("charlie", "SomePass123!"))  # expected error
    print("Test4:", cli.login(user2, pwd2))          # expected ok
    print("Test5:", cli.login("../etc/passwd", "Aa1!Aa1!Aa1!"))  # expected error

    srv.stop()
    srv.join()


if __name__ == "__main__":
    main()