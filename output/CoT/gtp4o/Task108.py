# 
# Chain-of-Through process:
# 1) Problem understanding:
#    - Implement a secure TCP server exposing a remote object store with commands:
#      AUTH, CREATE, READ, UPDATE, DELETE, LIST, QUIT. Clients manipulate server-side objects.
# 2) Security requirements:
#    - Validate inputs; authenticate clients; enforce value/key size; limit objects.
#    - Apply socket timeouts; limit line size; sanitize outputs; thread-safe shared state.
# 3) Secure coding generation:
#    - Use threading with locks; URL-encode outputs; refuse unauthenticated access.
# 4) Code review:
#    - No dynamic code exec; controlled resources; robust exception handling.
# 5) Secure code output:
#    - Final code includes 5 test cases connecting as clients.
#

import socket
import threading
import urllib.parse
from typing import List

AUTH_TOKEN = "Secr3tToken-Task108"
MAX_LINE_LEN = 2048
MAX_KEY_LEN = 64
MAX_VALUE_LEN = 1024
MAX_OBJECTS = 1000
CLIENT_TIMEOUT = 15.0
BACKLOG = 50

def is_valid_key(key: str) -> bool:
    if not key or len(key) > MAX_KEY_LEN:
        return False
    for ch in key:
        if not (ch.isalnum() or ch in ['_', '-']):
            return False
    return True

def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe='')

def url_decode(s: str) -> str:
    v = urllib.parse.unquote(s)
    if len(v) > MAX_VALUE_LEN:
        raise ValueError("Value too long")
    return v

class SecureObjectStore:
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def create(self, key: str, value: str) -> str:
        with self._lock:
            if len(self._store) >= MAX_OBJECTS:
                return "ERR STORE_FULL"
            if key in self._store:
                return "ERR EXISTS"
            self._store[key] = value
            return "OK CREATED"

    def read(self, key: str) -> str:
        with self._lock:
            if key not in self._store:
                return "ERR NOT_FOUND"
            return "OK " + url_encode(self._store[key])

    def update(self, key: str, value: str) -> str:
        with self._lock:
            if key not in self._store:
                return "ERR NOT_FOUND"
            self._store[key] = value
            return "OK UPDATED"

    def delete(self, key: str) -> str:
        with self._lock:
            if key not in self._store:
                return "ERR NOT_FOUND"
            del self._store[key]
            return "OK DELETED"

    def list_keys(self) -> str:
        with self._lock:
            keys = sorted(self._store.keys())
        return "OK " + url_encode(",".join(keys))

def process_command(store: SecureObjectStore, session: dict, line: str) -> str:
    if line is None:
        return "ERR EMPTY"
    line = line.rstrip("\r\n")
    if not line:
        return "ERR EMPTY"
    if len(line) > MAX_LINE_LEN:
        return "ERR TOO_LONG"
    parts = line.strip().split(" ", 2)
    cmd = parts[0].upper()

    if cmd == "AUTH":
        if len(parts) < 2:
            return "ERR BAD_AUTH"
        if parts[1] == AUTH_TOKEN:
            session['authed'] = True
            return "OK AUTHED"
        else:
            return "ERR BAD_AUTH"
    elif cmd == "QUIT":
        return "OK BYE"
    elif cmd == "LIST":
        if not session.get('authed'):
            return "ERR UNAUTH"
        return store.list_keys()
    elif cmd == "READ":
        if not session.get('authed'):
            return "ERR UNAUTH"
        if len(parts) < 2:
            return "ERR BAD_ARGS"
        key = parts[1]
        if not is_valid_key(key):
            return "ERR BAD_KEY"
        return store.read(key)
    elif cmd == "DELETE":
        if not session.get('authed'):
            return "ERR UNAUTH"
        if len(parts) < 2:
            return "ERR BAD_ARGS"
        key = parts[1]
        if not is_valid_key(key):
            return "ERR BAD_KEY"
        return store.delete(key)
    elif cmd in ("CREATE", "UPDATE"):
        if not session.get('authed'):
            return "ERR UNAUTH"
        if len(parts) < 3:
            return "ERR BAD_ARGS"
        key = parts[1]
        if not is_valid_key(key):
            return "ERR BAD_KEY"
        try:
            value = url_decode(parts[2])
        except Exception:
            return "ERR BAD_VALUE"
        if cmd == "CREATE":
            return store.create(key, value)
        else:
            return store.update(key, value)
    else:
        return "ERR UNKNOWN_CMD"

class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.store = SecureObjectStore()
        self._sock = None
        self._running = threading.Event()
        self._threads = []

    def start(self):
        if self._running.is_set():
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(BACKLOG)
        self._running.set()
        t = threading.Thread(target=self._accept_loop, name="Task108-Acceptor", daemon=True)
        t.start()
        self._threads.append(t)

    def _accept_loop(self):
        while self._running.is_set():
            try:
                client, addr = self._sock.accept()
                th = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
                th.start()
                self._threads.append(th)
            except OSError:
                break

    def _handle_client(self, client_sock: socket.socket):
        session = {'authed': False}
        with client_sock:
            client_sock.settimeout(CLIENT_TIMEOUT)
            buffer = b""
            try:
                while True:
                    chunk = client_sock.recv(1024)
                    if not chunk:
                        break
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if len(line) > MAX_LINE_LEN:
                            return
                        try:
                            text = line.decode("utf-8", errors="strict")
                        except UnicodeDecodeError:
                            text = ""
                        resp = process_command(self.store, session, text)
                        if "\n" in resp or "\r" in resp:
                            resp = "ERR INTERNAL"
                        client_sock.sendall((resp + "\n").encode("utf-8"))
                        if resp.startswith("OK BYE"):
                            return
            except socket.timeout:
                return
            except Exception:
                return

    def stop(self):
        self._running.clear()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

def client_interact(host: str, port: int, commands: List[str]) -> List[str]:
    resps: List[str] = []
    with socket.create_connection((host, port), timeout=3.0) as s:
        s.settimeout(5.0)
        for cmd in commands:
            if not cmd.endswith("\n"):
                cmd += "\n"
            s.sendall(cmd.encode("utf-8"))
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
            if data:
                resps.append(data.decode("utf-8").rstrip("\r\n"))
            else:
                resps.append("")
    return resps

if __name__ == "__main__":
    port = 19081
    server = Server("127.0.0.1", port)
    server.start()

    def show(name, resps):
        print("=== " + name + " ===")
        for r in resps:
            print(r)

    # Test 1
    t1 = [
        "AUTH " + AUTH_TOKEN,
        "CREATE hello " + url_encode("Hi World"),
        "READ hello",
        "QUIT"
    ]
    show("Test 1", client_interact("127.0.0.1", port, t1))

    # Test 2: No auth
    t2 = [
        "CREATE nope value",
        "READ nope",
        "QUIT"
    ]
    show("Test 2", client_interact("127.0.0.1", port, t2))

    # Test 3: Update and list
    t3 = [
        "AUTH " + AUTH_TOKEN,
        "CREATE k1 " + url_encode("v1"),
        "UPDATE k1 " + url_encode("new v1"),
        "LIST",
        "READ k1",
        "QUIT"
    ]
    show("Test 3", client_interact("127.0.0.1", port, t3))

    # Test 4: Delete
    t4 = [
        "AUTH " + AUTH_TOKEN,
        "CREATE toDel " + url_encode("temp"),
        "DELETE toDel",
        "READ toDel",
        "QUIT"
    ]
    show("Test 4", client_interact("127.0.0.1", port, t4))

    # Test 5: Bad key and too long value
    big_val = "A" * (MAX_VALUE_LEN + 5)
    t5 = [
        "AUTH " + AUTH_TOKEN,
        "CREATE bad!key " + url_encode("value"),
        "CREATE okkey " + url_encode(big_val),
        "QUIT"
    ]
    show("Test 5", client_interact("127.0.0.1", port, t5))

    server.stop()