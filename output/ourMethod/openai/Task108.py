import socket
import threading
from typing import Dict, List, Tuple

# Validation helpers
def is_valid_id_or_key(s: str) -> bool:
    if s is None or len(s) < 1 or len(s) > 64:
        return False
    return all(c.isalnum() or c == '_' for c in s)

def is_valid_value(s: str) -> bool:
    if s is None or len(s) > 256:
        return False
    for c in s:
        if c == ' ':
            continue
        if ord(c) < 33 or ord(c) > 126:
            return False
    return True

class ObjectStore:
    def __init__(self) -> None:
        self.store: Dict[str, Dict[str, str]] = {}
        self.lock = threading.Lock()

    def new_object(self, oid: str) -> str:
        if not is_valid_id_or_key(oid):
            return "ERR invalid_id"
        with self.lock:
            if oid in self.store:
                return "ERR exists"
            self.store[oid] = {}
            return "OK"

    def put_field(self, oid: str, key: str, value: str) -> str:
        if not is_valid_id_or_key(oid):
            return "ERR invalid_id"
        if not is_valid_id_or_key(key):
            return "ERR invalid_key"
        if not is_valid_value(value):
            return "ERR invalid_value"
        with self.lock:
            if oid not in self.store:
                return "ERR not_found"
            self.store[oid][key] = value
            return "OK"

    def get_field(self, oid: str, key: str) -> str:
        if not is_valid_id_or_key(oid):
            return "ERR invalid_id"
        if not is_valid_id_or_key(key):
            return "ERR invalid_key"
        with self.lock:
            if oid not in self.store:
                return "ERR not_found"
            if key not in self.store[oid]:
                return "ERR not_found"
            return "OK " + self.store[oid][key]

    def del_field(self, oid: str, key: str) -> str:
        if not is_valid_id_or_key(oid):
            return "ERR invalid_id"
        if not is_valid_id_or_key(key):
            return "ERR invalid_key"
        with self.lock:
            if oid not in self.store:
                return "ERR not_found"
            if key not in self.store[oid]:
                return "ERR not_found"
            del self.store[oid][key]
            return "OK"

    def keys(self, oid: str) -> str:
        if not is_valid_id_or_key(oid):
            return "ERR invalid_id"
        with self.lock:
            if oid not in self.store:
                return "ERR not_found"
            ks = sorted(self.store[oid].keys())
            return "OK " + ",".join(ks)

    def drop(self, oid: str) -> str:
        if not is_valid_id_or_key(oid):
            return "ERR invalid_id"
        with self.lock:
            if oid not in self.store:
                return "ERR not_found"
            del self.store[oid]
            return "OK"

def process_command(line: str, store: ObjectStore) -> str:
    if line is None:
        return "ERR empty"
    line = line.strip()
    if not line:
        return "ERR empty"
    parts = line.split(' ')
    cmd = parts[0].upper()
    try:
        if cmd == "PING":
            return "OK PONG"
        if cmd == "NEW" and len(parts) == 2:
            return store.new_object(parts[1])
        if cmd == "PUT" and len(parts) == 4:
            return store.put_field(parts[1], parts[2], parts[3])
        if cmd == "GET" and len(parts) == 3:
            return store.get_field(parts[1], parts[2])
        if cmd == "DEL" and len(parts) == 3:
            return store.del_field(parts[1], parts[2])
        if cmd == "KEYS" and len(parts) == 2:
            return store.keys(parts[1])
        if cmd == "DROP" and len(parts) == 2:
            return store.drop(parts[1])
        if cmd == "QUIT":
            return "OK BYE"
        return "ERR unknown"
    except Exception:
        return "ERR error"

class Server:
    def __init__(self, port: int = 0) -> None:
        self.store = ObjectStore()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.running = True
        self.thread = threading.Thread(target=self.accept_loop, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def get_port(self) -> int:
        return self.sock.getsockname()[1]

    def accept_loop(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
                conn.settimeout(10.0)
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
            except OSError:
                break

    def handle_client(self, conn: socket.socket) -> None:
        with conn:
            data = b""
            max_line = 1024
            while True:
                try:
                    chunk = conn.recv(256)
                    if not chunk:
                        break
                    data += chunk
                    while b"\n" in data:
                        line, data = data.split(b"\n", 1)
                        if len(line) > max_line:
                            conn.sendall(b"ERR too_long\n")
                            continue
                        try:
                            text = line.decode("utf-8", errors="strict")
                        except UnicodeDecodeError:
                            conn.sendall(b"ERR encoding\n")
                            continue
                        resp = process_command(text, self.store)
                        conn.sendall((resp + "\n").encode("utf-8"))
                        if resp == "OK BYE":
                            return
                    if len(data) > max_line:
                        conn.sendall(b"ERR too_long\n")
                        data = b""
                except socket.timeout:
                    break
                except Exception:
                    break

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass

def send_commands(host: str, port: int, commands: List[str]) -> List[str]:
    res: List[str] = []
    with socket.create_connection((host, port), timeout=3.0) as s:
        s.settimeout(3.0)
        for cmd in commands:
            s.sendall((cmd + "\n").encode("utf-8"))
            resp = recv_line(s, 1024)
            res.append(resp if resp is not None else "ERR no_response")
        s.sendall(b"QUIT\n")
        recv_line(s, 1024)
    return res

def recv_line(s: socket.socket, max_len: int) -> str | None:
    data = b""
    while len(data) < max_len:
        chunk = s.recv(1)
        if not chunk:
            break
        if chunk == b"\n":
            break
        if chunk == b"\r":
            continue
        data += chunk
    if not data:
        return None
    if len(data) >= max_len:
        return "ERR too_long"
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return "ERR encoding"

def main() -> None:
    srv = Server(0)
    srv.start()
    port = srv.get_port()

    # 5 test cases
    t1 = send_commands("127.0.0.1", port, ["NEW objA"])
    print("Test1:", t1[0])

    t2 = send_commands("127.0.0.1", port, ["PUT objA key1 v1"])
    print("Test2:", t2[0])

    t3 = send_commands("127.0.0.1", port, ["GET objA key1"])
    print("Test3:", t3[0])

    t4 = send_commands("127.0.0.1", port, ["KEYS objA"])
    print("Test4:", t4[0])

    t5 = send_commands("127.0.0.1", port, ["DEL objA key1", "GET objA key1"])
    print("Test5a:", t5[0])
    print("Test5b:", t5[1])

    srv.close()

if __name__ == "__main__":
    main()