import socket
import threading
import time
from typing import Optional, Tuple

# Step 1: Problem understanding: multi-client chat server with broadcast.
# Step 2: Security: limit clients, message size, timeouts, sanitize, local bind.
# Step 3-5: Implementation with safe patterns, reviewed, and final output.

class _PyChatServer:
    def __init__(self, max_clients: int = 16):
        self.max_clients = max(1, max_clients)
        self._srv_sock: Optional[socket.socket] = None
        self._running = threading.Event()
        self._clients = []
        self._clients_lock = threading.Lock()
        self._accept_thread: Optional[threading.Thread] = None
        self._SOCKET_TIMEOUT = 15
        self._MAX_MSG_LEN = 1024

    def start(self, port: int) -> int:
        if self._running.is_set():
            raise RuntimeError("Server already running")
        self._srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv_sock.bind(("127.0.0.1", port))
        self._srv_sock.listen(50)
        self._srv_sock.settimeout(1.0)
        self._running.set()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        return self._srv_sock.getsockname()[1]

    def stop(self):
        self._running.clear()
        if self._srv_sock:
            try: self._srv_sock.close()
            except OSError: pass
        with self._clients_lock:
            for c in list(self._clients):
                try: c.close()
                except OSError: pass
            self._clients.clear()
        if self._accept_thread:
            self._accept_thread.join(timeout=2)

    def _accept_loop(self):
        while self._running.is_set():
            try:
                conn, addr = self._srv_sock.accept()
                conn.settimeout(self._SOCKET_TIMEOUT)
                with self._clients_lock:
                    if len(self._clients) >= self.max_clients:
                        conn.close()
                        continue
                    self._clients.append(conn)
                self._send(conn, b"[Server]: Welcome!\n")
                threading.Thread(target=self._client_handler, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _client_handler(self, conn: socket.socket):
        try:
            buf = bytearray()
            last = time.time()
            while self._running.is_set():
                try:
                    b = conn.recv(1)
                    if not b:
                        break
                    last = time.time()
                    if b == b'\n':
                        msg = bytes(buf).decode('utf-8', errors='ignore')
                        buf.clear()
                        if msg.strip().lower() == "quit":
                            break
                        self._broadcast(self._sanitize(msg), conn)
                    elif b != b'\r':
                        if len(buf) < self._MAX_MSG_LEN:
                            buf.extend(b)
                        else:
                            self._send(conn, b"[Server]: Message too long. Disconnecting.\n")
                            break
                    if time.time() - last > 2 * self._SOCKET_TIMEOUT:
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break
        finally:
            with self._clients_lock:
                try:
                    self._clients.remove(conn)
                except ValueError:
                    pass
            try: conn.close()
            except OSError: pass

    def _send(self, conn: socket.socket, data: bytes):
        try:
            conn.sendall(data)
        except OSError:
            pass

    def _broadcast(self, message: str, src: socket.socket):
        if not message:
            return
        try:
            src_idx = self._clients.index(src)
        except ValueError:
            src_idx = -1
        data = f"[Client-{src_idx if src_idx >=0 else 'X'}]: {message}\n".encode("utf-8")
        with self._clients_lock:
            for c in list(self._clients):
                if c is not src:
                    self._send(c, data)

    @staticmethod
    def _sanitize(msg: str) -> str:
        if not msg:
            return ""
        out = []
        for ch in msg:
            if 32 <= ord(ch) != 127:
                out.append(ch)
            if len(out) >= 1024:
                break
        return "".join(out).strip()

def start_server(port: int, max_clients: int) -> Tuple[int, _PyChatServer]:
    srv = _PyChatServer(max_clients=max_clients)
    actual_port = srv.start(port)
    return actual_port, srv

def stop_server(server: _PyChatServer) -> None:
    if server:
        server.stop()

# Simple client for tests
def _client_send_and_receive(host: str, port: int, message: str, expect_reads: int, timeout: float):
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            s.settimeout(timeout)
            s.sendall((message + "\n").encode("utf-8"))
            for _ in range(expect_reads):
                try:
                    line = _recv_line(s, 2048, timeout)
                    if not line:
                        break
                except socket.timeout:
                    break
            s.sendall(b"quit\n")
    except OSError:
        pass

def _recv_line(sock: socket.socket, maxlen: int, timeout: float) -> Optional[str]:
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < maxlen:
        b = sock.recv(1)
        if not b:
            break
        if b == b'\n':
            break
        if b != b'\r':
            buf.extend(b)
    return buf.decode("utf-8", errors="ignore") if buf else ""

if __name__ == "__main__":
    port, server = start_server(0, 16)
    threads = []
    for i in range(5):
        t = threading.Thread(target=_client_send_and_receive, args=("127.0.0.1", port, f"Hello from Python client {i}", 3, 3.0))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    stop_server(server)
    # print("Python server test completed.")