import os
import socket
import threading
import time

class RemoteObjectServer:
    def __init__(self, host: str, port: int, secret: str):
        self.host = host
        self.port = port
        self.secret = secret.encode('utf-8')
        self.counter = 0
        self.kv = {}
        self.running = False
        self.sock = None
        self.lock = threading.RLock()

    def start(self) -> bool:
        if self.running:
            return True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(50)
            self.running = True
            threading.Thread(target=self._accept_loop, daemon=True).start()
            return True
        except Exception:
            return False

    def stop(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    @staticmethod
    def _const_time_eq(a: bytes, b: bytes) -> bool:
        if a is None or b is None:
            return False
        if len(a) != len(b):
            # constant-time-ish handling
            result = len(a) ^ len(b)
            m = min(len(a), len(b))
            for i in range(m):
                result |= a[i] ^ b[i]
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    @staticmethod
    def _is_key_valid(k: str) -> bool:
        if not k or len(k) > 32:
            return False
        for ch in k:
            if not (ch.isalnum() or ch in ['_', '-']):
                return False
        return True

    def _accept_loop(self):
        while self.running:
            try:
                client, _ = self.sock.accept()
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except Exception:
                if not self.running:
                    break

    @staticmethod
    def _read_line_limited(conn: socket.socket, max_len: int, timeout: float):
        conn.settimeout(timeout)
        buf = bytearray()
        start = time.time()
        while True:
            if time.time() - start > timeout:
                raise TimeoutError()
            try:
                ch = conn.recv(1)
            except socket.timeout:
                continue
            if not ch:
                if not buf:
                    return None
                break
            if ch == b'\n':
                break
            if ch != b'\r':
                if len(buf) >= max_len:
                    raise ValueError("line too long")
                buf += ch
        return buf.decode('utf-8', errors='strict').strip()

    def _writeln(self, conn: socket.socket, s: str):
        try:
            conn.sendall((s + "\n").encode('utf-8'))
        except Exception:
            pass

    def _handle_client(self, conn: socket.socket):
        with conn:
            self._writeln(conn, "WELCOME")
            try:
                line = self._read_line_limited(conn, 1024, 10.0)
            except Exception:
                self._writeln(conn, "ERR AUTH")
                return
            if not line or not line.startswith("TOKEN "):
                self._writeln(conn, "ERR AUTH")
                return
            token = line[6:].strip().encode('utf-8')
            if not self._const_time_eq(token, self.secret):
                self._writeln(conn, "ERR AUTH")
                return
            self._writeln(conn, "OK AUTH")
            while True:
                try:
                    cmdline = self._read_line_limited(conn, 1024, 15.0)
                except Exception:
                    break
                if cmdline is None:
                    break
                if not cmdline:
                    continue
                parts = cmdline.split()
                cmd = parts[0].upper()
                if cmd == "QUIT":
                    self._writeln(conn, "BYE")
                    return
                elif cmd == "PING":
                    self._writeln(conn, "PONG")
                elif cmd == "GETCNT":
                    with self.lock:
                        v = self.counter
                    self._writeln(conn, f"COUNTER {v}")
                elif cmd == "INCR" and len(parts) == 2:
                    try:
                        n = int(parts[1])
                        if n < 0 or n > 1_000_000:
                            self._writeln(conn, "ERR RANGE")
                        else:
                            with self.lock:
                                self.counter += n
                                v = self.counter
                            self._writeln(conn, f"OK {v}")
                    except ValueError:
                        self._writeln(conn, "ERR ARG")
                elif cmd == "DECR" and len(parts) == 2:
                    try:
                        n = int(parts[1])
                        if n < 0 or n > 1_000_000:
                            self._writeln(conn, "ERR RANGE")
                        else:
                            with self.lock:
                                if self.counter - n < 0:
                                    self._writeln(conn, "ERR RANGE")
                                else:
                                    self.counter -= n
                                    v = self.counter
                                    self._writeln(conn, f"OK {v}")
                    except ValueError:
                        self._writeln(conn, "ERR ARG")
                elif cmd == "RESET":
                    with self.lock:
                        self.counter = 0
                    self._writeln(conn, "OK 0")
                elif cmd == "PUT" and len(parts) == 3:
                    key, val = parts[1], parts[2]
                    if not self._is_key_valid(key) or len(val) > 256:
                        self._writeln(conn, "ERR ARG")
                    else:
                        with self.lock:
                            self.kv[key] = val
                        self._writeln(conn, "OK")
                elif cmd == "GET" and len(parts) == 2:
                    key = parts[1]
                    if not self._is_key_valid(key):
                        self._writeln(conn, "ERR ARG")
                    else:
                        with self.lock:
                            v = self.kv.get(key)
                        if v is None:
                            self._writeln(conn, "ERR NOT_FOUND")
                        else:
                            self._writeln(conn, f"VALUE {v}")
                elif cmd == "DEL" and len(parts) == 2:
                    key = parts[1]
                    if not self._is_key_valid(key):
                        self._writeln(conn, "ERR ARG")
                    else:
                        with self.lock:
                            self.kv.pop(key, None)
                        self._writeln(conn, "OK")
                elif cmd == "LIST":
                    with self.lock:
                        keys = sorted(self.kv.keys())
                    self._writeln(conn, "KEYS " + ",".join(keys))
                else:
                    self._writeln(conn, "ERR CMD")

def client_session(host: str, port: int, token: str, commands):
    out = []
    try:
        s = socket.create_connection((host, port), timeout=3.0)
        s.settimeout(5.0)
        f = s.makefile('rwb', buffering=0)
        def read_line():
            line = f.readline()
            return line.decode('utf-8').rstrip("\n") if line else ""
        def write_line(x: str):
            f.write((x + "\n").encode('utf-8'))
            f.flush()
        out.append(read_line())  # welcome
        write_line("TOKEN " + token)
        out.append(read_line())  # auth
        if not out[-1].startswith("OK"):
            s.close()
            return out
        for cmd in commands:
            write_line(cmd)
            out.append(read_line())
        s.close()
    except Exception:
        out.append("ERR IO")
    return out

def main():
    port = 50508
    secret = os.environ.get("REMOTE_SECRET", "s3cure-Secret-Token")
    srv = RemoteObjectServer("127.0.0.1", port, secret)
    if not srv.start():
        print("Failed to start")
        return
    time.sleep(0.2)

    # 5 test cases
    t1 = client_session("127.0.0.1", port, secret, ["PING", "QUIT"])
    print("Test1:", t1)

    t2 = client_session("127.0.0.1", port, secret, ["GETCNT", "INCR 5", "GETCNT", "QUIT"])
    print("Test2:", t2)

    t3 = client_session("127.0.0.1", port, secret, ["PUT foo bar", "GET foo", "QUIT"])
    print("Test3:", t3)

    t4 = client_session("127.0.0.1", port, secret, ["DEL foo", "GET foo", "QUIT"])
    print("Test4:", t4)

    t5 = client_session("127.0.0.1", port, "wrong-token", ["PING", "QUIT"])
    print("Test5:", t5)

    srv.stop()

if __name__ == "__main__":
    main()