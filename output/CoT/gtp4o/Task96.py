import socket
import threading
import time

# Chain-of-Through process:
# 1. Understand: Implement a TCP echo server that listens on a given port and echoes received messages.
# 2. Security: Bind to localhost, set timeouts, limit input size, handle exceptions, clean up resources.
# 3. Secure implementation: Use per-client threads with daemon, enforce max line length and timeouts.
# 4. Review: Ensure sockets are closed, safe decoding, and controlled thread creation.
# 5. Output: Final secure code.

MAX_LINE = 8192
CLIENT_TIMEOUT = 30.0
ACCEPT_TIMEOUT = 1.0
BACKLOG = 50

class EchoServer:
    def __init__(self):
        self._sock = None
        self._running = threading.Event()
        self._accept_thread = None

    def start(self, port: int) -> int:
        if self._running.is_set():
            raise RuntimeError("Server already running")
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(BACKLOG)
        self._sock.settimeout(ACCEPT_TIMEOUT)
        actual_port = self._sock.getsockname()[1]
        self._running.set()
        self._accept_thread = threading.Thread(target=self._accept_loop, name="PyEcho-Acceptor", daemon=True)
        self._accept_thread.start()
        return actual_port

    def _accept_loop(self):
        while self._running.is_set():
            try:
                conn, addr = self._sock.accept()
                t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _readline_limited(self, conn: socket.socket) -> bytes:
        data = bytearray()
        while True:
            try:
                chunk = conn.recv(1)
            except socket.timeout:
                raise
            if not chunk:
                return None if not data else bytes(data)
            if chunk == b'\n':
                break
            if chunk != b'\r':
                if len(data) >= MAX_LINE:
                    raise ValueError("Input line too long")
                data.extend(chunk)
        return bytes(data)

    def _handle_client(self, conn: socket.socket):
        with conn:
            conn.settimeout(CLIENT_TIMEOUT)
            try:
                while True:
                    line = self._readline_limited(conn)
                    if line is None:
                        break
                    conn.sendall(line + b'\n')
            except (socket.timeout, ValueError, OSError):
                # Close connection on error or timeout
                pass

    def stop(self):
        self._running.clear()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None


def start_echo_server(port: int) -> int:
    global _server_instance
    _server_instance = EchoServer()
    return _server_instance.start(port)

def stop_echo_server():
    global _server_instance
    if _server_instance is not None:
        _server_instance.stop()
        _server_instance = None

def echo_client(host: str, port: int, message: str) -> str:
    with socket.create_connection((host, port), timeout=5.0) as s:
        s.settimeout(CLIENT_TIMEOUT)
        s.sendall((message + "\n").encode("utf-8"))
        # Read until newline with limit
        data = bytearray()
        while True:
            b = s.recv(1)
            if not b:
                break
            if b == b'\n':
                break
            if b != b'\r':
                if len(data) >= MAX_LINE:
                    raise ValueError("Response line too long")
                data.extend(b)
        return data.decode("utf-8", errors="strict")

_server_instance = None

if __name__ == "__main__":
    port = start_echo_server(0)
    host = "127.0.0.1"
    tests = [
        "Hello",
        "",
        "The quick brown fox jumps over the lazy dog",
        "1234567890!@#$%^&*()_+",
        "Unicode: Привет, こんにちは, 🙂",
    ]
    for i, t in enumerate(tests, 1):
        resp = echo_client(host, port, t)
        print(f"Test {i} -> {resp}")
    stop_echo_server()