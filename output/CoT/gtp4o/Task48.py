import socket
import threading
import time

class ChatServerPy:
    def __init__(self, port: int = 0):
        self._requested_port = port
        self._sock = None
        self._running = False
        self._accept_thread = None
        self._clients = []
        self._clients_lock = threading.Lock()
        self._client_counter = 0

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("127.0.0.1", self._requested_port))
            self._sock.listen(50)
            self._sock.settimeout(0.5)
            self._running = True
            self._accept_thread = threading.Thread(target=self._accept_loop, name="PyAccept", daemon=True)
            self._accept_thread.start()
            return True
        except Exception:
            return False

    def get_port(self) -> int:
        if not self._sock:
            return -1
        return self._sock.getsockname()[1]

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                try:
                    conn.settimeout(0.5)
                    self._client_counter += 1
                    name = f"Client-{self._client_counter}"
                    handler = {"sock": conn, "name": name, "alive": True, "lock": threading.Lock()}
                    with self._clients_lock:
                        self._clients.append(handler)
                    threading.Thread(target=self._client_thread, args=(handler,), name=f"PyHandler-{name}", daemon=True).start()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    continue

    def _sanitize(self, s: str) -> str:
        if s is None:
            return ""
        s = s.replace("\r", " ").replace("\n", " ").strip()
        if len(s) > 1024:
            s = s[:1024]
        return s

    def broadcast(self, msg: str, sender: dict | None):
        payload = self._sanitize(msg)
        if sender:
            payload = f"{sender['name']}: {payload}"
        with self._clients_lock:
            clients_snapshot = list(self._clients)
        data = (payload + "\n").encode("utf-8", "replace")
        for c in clients_snapshot:
            try:
                with c["lock"]:
                    c["sock"].sendall(data)
            except Exception:
                self._close_client(c)

    def _client_thread(self, handler: dict):
        conn = handler["sock"]
        buf = b""
        try:
            while handler["alive"]:
                try:
                    chunk = conn.recv(1024)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        text = line.decode("utf-8", "replace")
                    except Exception:
                        text = ""
                    text = self._sanitize(text)
                    if text:
                        self.broadcast(text, handler)
        except Exception:
            pass
        finally:
            self._close_client(handler)

    def _close_client(self, handler: dict):
        if not handler.get("alive", False):
            return
        handler["alive"] = False
        try:
            handler["sock"].close()
        except Exception:
            pass
        with self._clients_lock:
            try:
                self._clients.remove(handler)
            except ValueError:
                pass

    def stop(self):
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        with self._clients_lock:
            clients_snapshot = list(self._clients)
        for c in clients_snapshot:
            self._close_client(c)
        if self._accept_thread:
            self._accept_thread.join(timeout=1.0)

class ChatClientPy:
    def __init__(self, name: str):
        self.name = name
        self.sock = None
        self.running = False
        self.recv_thread = None
        self.received = []
        self._lock = threading.Lock()

    def connect(self, host: str, port: int) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(1.0)
            self.sock.connect((host, port))
            self.sock.settimeout(0.5)
            self.running = True
            self.recv_thread = threading.Thread(target=self._recv_loop, name=f"PyReader-{self.name}", daemon=True)
            self.recv_thread.start()
            return True
        except Exception:
            return False

    def _recv_loop(self):
        buf = b""
        while self.running:
            try:
                chunk = self.sock.recv(1024)
            except socket.timeout:
                continue
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    text = line.decode("utf-8", "replace")
                except Exception:
                    text = ""
                with self._lock:
                    self.received.append(text)
        self.running = False

    def send(self, msg: str) -> bool:
        if not self.running:
            return False
        if msg is None:
            msg = ""
        msg = msg.replace("\r", " ").replace("\n", " ")
        if len(msg) > 1024:
            msg = msg[:1024]
        try:
            self.sock.sendall((msg + "\n").encode("utf-8", "replace"))
            return True
        except Exception:
            return False

    def get_received_snapshot(self):
        with self._lock:
            return list(self.received)

    def close(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        if self.recv_thread:
            self.recv_thread.join(timeout=1.0)

def _wait_for(cond, timeout=2.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()

def main():
    server = ChatServerPy(0)
    assert server.start()
    port = server.get_port()
    print(f"Py Server on {port}")

    # Test 1
    c1 = ChatClientPy("T1-C1")
    c1.connect("127.0.0.1", port)
    c1.send("Hello World")
    _wait_for(lambda: len(c1.get_received_snapshot()) >= 1, 2.0, 0.05)
    print("Py Test1:", c1.get_received_snapshot())

    # Test 2
    c2 = ChatClientPy("T2-C2")
    c2.connect("127.0.0.1", port)
    c1.send("Ping")
    _wait_for(lambda: any("Ping" in m for m in c2.get_received_snapshot()), 2.0, 0.05)
    print("Py Test2 C2:", c2.get_received_snapshot())

    # Test 3
    c2.send("Pong")
    c1.send("Another")
    _wait_for(lambda: len(c1.get_received_snapshot()) >= 3 and len(c2.get_received_snapshot()) >= 2, 3.0, 0.05)
    print("Py Test3 C1:", c1.get_received_snapshot())
    print("Py Test3 C2:", c2.get_received_snapshot())

    # Test 4
    c1.close()
    c2.send("AfterC1Left")
    _wait_for(lambda: any("AfterC1Left" in m for m in c2.get_received_snapshot()), 2.0, 0.05)
    print("Py Test4 C2:", c2.get_received_snapshot())

    # Test 5
    c3 = ChatClientPy("T5-C3")
    c3.connect("127.0.0.1", port)
    c2.send("WelcomeNew")
    _wait_for(lambda: any("WelcomeNew" in m for m in c3.get_received_snapshot()), 2.0, 0.05)
    print("Py Test5 C3:", c3.get_received_snapshot())

    c2.close()
    c3.close()
    server.stop()
    print("Py Done")

if __name__ == "__main__":
    main()