import socket
import threading
import time
from typing import List, Tuple

class ChatServer:
    def __init__(self) -> None:
        self._sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._running = threading.Event()
        self._clients_lock = threading.Lock()
        self._clients: List[Tuple[socket.socket, str]] = []
        self._client_id = 1

    def start(self, port: int) -> None:
        if self._running.is_set():
            raise RuntimeError("Server already running")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(20)
        s.settimeout(1.0)
        self._sock = s
        self._running.set()
        self._accept_thread = threading.Thread(target=self._accept_loop, name="accept", daemon=True)
        self._accept_thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        with self._clients_lock:
            for c, _ in list(self._clients):
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    c.close()
                except OSError:
                    pass
            self._clients.clear()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=3.0)

    def get_port(self) -> int:
        if self._sock is None:
            return -1
        return self._sock.getsockname()[1]

    @staticmethod
    def _sanitize(text: str, max_len: int = 1024) -> str:
        if text is None:
            return ""
        if len(text) > max_len:
            text = text[:max_len]
        out_chars: List[str] = []
        for ch in text:
            if ch in ("\n", "\r"):
                continue
            oc = ord(ch)
            if 32 <= oc <= 126 or ch.isalnum() or ch.isspace():
                out_chars.append(ch)
            else:
                out_chars.append("?")
        return "".join(out_chars)

    def _broadcast(self, msg: str) -> None:
        data = (msg + "\n").encode("utf-8", errors="replace")
        dead: List[Tuple[socket.socket, str]] = []
        with self._clients_lock:
            for c, _ in self._clients:
                try:
                    ChatServer._send_all(c, data)
                except OSError:
                    dead.append((c, ""))
            # Cleanup
            for d, _ in dead:
                try:
                    d.close()
                except OSError:
                    pass
                self._clients = [(c, n) for (c, n) in self._clients if c is not d]

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while self._running.is_set():
            try:
                c, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._running.is_set():
                    time.sleep(0.05)
                continue
            try:
                c.settimeout(15.0)
                name = f"client-{self._client_id}"
                self._client_id += 1
                with self._clients_lock:
                    self._clients.append((c, name))
                self._broadcast(f"[server] {name} joined")
                t = threading.Thread(target=self._client_thread, args=(c, name), daemon=True)
                t.start()
            except Exception:
                try:
                    c.close()
                except OSError:
                    pass

    def _client_thread(self, c: socket.socket, name: str) -> None:
        try:
            buf = b""
            while self._running.is_set():
                try:
                    chunk = c.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        text = line.decode("utf-8", errors="replace")
                    except Exception:
                        text = ""
                    text = text.rstrip("\r")
                    if text.strip().lower() == "/quit":
                        raise SystemExit
                    clean = self._sanitize(text)
                    if clean:
                        self._broadcast(f"{name}: {clean}")
        except SystemExit:
            pass
        except Exception:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass
            with self._clients_lock:
                self._clients = [(sc, n) for (sc, n) in self._clients if sc is not c]
            self._broadcast(f"[server] {name} left")

    @staticmethod
    def _send_all(sock: socket.socket, data: bytes) -> None:
        total = 0
        while total < len(data):
            sent = sock.send(data[total:])
            if sent <= 0:
                raise OSError("send failed")
            total += sent


# Test harness with 5 clients
def run_test() -> None:
    server = ChatServer()
    server.start(0)
    port = server.get_port()
    host = "127.0.0.1"
    clients = 5
    start_event = threading.Event()
    ready_count = {"n": 0}
    ready_lock = threading.Lock()

    class TestClient(threading.Thread):
        def __init__(self, idx: int, expect: int) -> None:
            super().__init__(daemon=True)
            self.idx = idx
            self.expect = expect
            self.received = 0

        def run(self) -> None:
            try:
                s = socket.create_connection((host, port), timeout=5.0)
                s.settimeout(15.0)
                with ready_lock:
                    ready_count["n"] += 1
                start_event.wait(5.0)
                msg = f"Hello from test client {self.idx}\n".encode("utf-8")
                ChatServer._send_all(s, msg)
                deadline = time.time() + 5.0
                data = b""
                inbox: List[str] = []
                while time.time() < deadline and len(inbox) < self.expect:
                    try:
                        chunk = s.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
                    while b"\n" in data:
                        line, data = data.split(b"\n", 1)
                        try:
                            text = line.decode("utf-8", errors="replace").rstrip("\r")
                        except Exception:
                            text = ""
                        if text:
                            inbox.append(text)
                self.received = len(inbox)
                ChatServer._send_all(s, b"/quit\n")
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()
            except Exception:
                pass

    expected_min = clients  # expected chat messages
    tcs = [TestClient(i + 1, expected_min) for i in range(clients)]
    for t in tcs:
        t.start()

    # Wait for all clients ready
    for _ in range(50):
        with ready_lock:
            if ready_count["n"] >= clients:
                break
        time.sleep(0.05)
    start_event.set()

    for t in tcs:
        t.join()

    for i, t in enumerate(tcs, 1):
        print(f"Client {i} received {t.received} lines")

    server.stop()
    print("Server stopped.")

if __name__ == "__main__":
    run_test()