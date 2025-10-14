import socket
import selectors
import threading
import time
import sys

MAX_MSG_LEN = 512
CLIENT_IDLE_TIMEOUT_SEC = 60
DEFAULT_MAX_CLIENTS = 100

def is_valid_port(port: int) -> bool:
    return isinstance(port, int) and 1024 <= port <= 65535

def sanitize_message(msg: str, max_len: int) -> str:
    if msg is None:
        return ""
    out_chars = []
    count = 0
    for ch in msg:
        if count >= max_len:
            break
        code = ord(ch)
        if ch in "\r\n":
            if len(out_chars) == 0 or out_chars[-1] != ' ':
                out_chars.append(' ')
                count += 1
        elif ch == '\t' or (code >= 0x20 and not (0x7F <= code <= 0x9F)):
            out_chars.append(ch)
            count += 1
        # else: skip control chars
    result = ''.join(out_chars).strip()
    if len(result) > max_len:
        result = result[:max_len]
    return result

class ChatServer:
    def __init__(self, port: int, max_clients: int):
        self.port = port
        self.max_clients = max(1, int(max_clients))
        self.selector = selectors.DefaultSelector()
        self.server_sock = None
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        self.clients = {}  # sock -> last_active_time
        self.buffers = {}  # sock -> bytes buffer

    def start(self) -> bool:
        if not is_valid_port(self.port):
            return False
        if self.running:
            return True
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("0.0.0.0", self.port))
            self.server_sock.listen(min(self.max_clients, 50))
            self.server_sock.setblocking(False)
            self.selector.register(self.server_sock, selectors.EVENT_READ, self._accept)
            self.running = True
            self.thread = threading.Thread(target=self._run, name="chat-server", daemon=True)
            self.thread.start()
            return True
        except OSError:
            self.stop()
            return False

    def stop(self):
        self.running = False
        try:
            if self.server_sock:
                try:
                    self.selector.unregister(self.server_sock)
                except Exception:
                    pass
                self.server_sock.close()
        except Exception:
            pass
        finally:
            self.server_sock = None
        with self.lock:
            socks = list(self.clients.keys())
        for s in socks:
            self._close_client(s)
        try:
            self.selector.close()
        except Exception:
            pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        self.thread = None

    def _run(self):
        while self.running:
            try:
                events = self.selector.select(timeout=1.0)
            except Exception:
                break
            now = time.time()
            # Handle events
            for key, mask in events:
                callback = key.data
                try:
                    callback(key.fileobj)
                except Exception:
                    if isinstance(key.fileobj, socket.socket):
                        self._close_client(key.fileobj)
            # Handle idle timeouts
            with self.lock:
                for s, last in list(self.clients.items()):
                    if now - last > CLIENT_IDLE_TIMEOUT_SEC:
                        self._close_client(s)

    def _accept(self, server_sock: socket.socket):
        try:
            client_sock, addr = server_sock.accept()
            client_sock.setblocking(False)
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self.lock:
                if len(self.clients) >= self.max_clients:
                    client_sock.close()
                    return
                self.clients[client_sock] = time.time()
                self.buffers[client_sock] = b""
            self.selector.register(client_sock, selectors.EVENT_READ, self._read_client)
            self._send_line(client_sock, "Welcome to Secure Chat Server")
        except Exception:
            pass

    def _read_client(self, client_sock: socket.socket):
        try:
            data = client_sock.recv(1024)
            if not data:
                self._close_client(client_sock)
                return
            with self.lock:
                self.clients[client_sock] = time.time()
                buf = self.buffers.get(client_sock, b"") + data
                # Process complete lines
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        text = line.decode('utf-8', errors='ignore')
                    except Exception:
                        text = ""
                    msg = sanitize_message(text, MAX_MSG_LEN)
                    if msg:
                        self._broadcast(msg, exclude=client_sock)
                self.buffers[client_sock] = buf[:MAX_MSG_LEN]  # cap buffer
        except Exception:
            self._close_client(client_sock)

    def _broadcast(self, message: str, exclude: socket.socket = None):
        data = (message + "\n").encode('utf-8')
        with self.lock:
            recipients = [s for s in self.clients.keys() if s != exclude]
        for s in recipients:
            try:
                s.sendall(data)
            except Exception:
                self._close_client(s)

    def _send_line(self, s: socket.socket, message: str):
        try:
            s.sendall((message + "\n").encode('utf-8'))
        except Exception:
            self._close_client(s)

    def _close_client(self, s: socket.socket):
        with self.lock:
            try:
                if s in self.clients:
                    del self.clients[s]
                if s in self.buffers:
                    del self.buffers[s]
            except Exception:
                pass
        try:
            try:
                self.selector.unregister(s)
            except Exception:
                pass
            s.close()
        except Exception:
            pass

def _run_tests():
    passed = 0
    if sanitize_message("Hello\0World", MAX_MSG_LEN) == "HelloWorld":
        passed += 1
    if len(sanitize_message("a" * 600, 128)) == 128:
        passed += 1
    if is_valid_port(8080):
        passed += 1
    if not is_valid_port(70000):
        passed += 1
    if not is_valid_port(1023):
        passed += 1
    print(f"Tests passed: {passed}/5")

if __name__ == "__main__":
    _run_tests()
    if len(sys.argv) >= 2:
        try:
            port = int(sys.argv[1])
            srv = ChatServer(port, DEFAULT_MAX_CLIENTS)
            if srv.start():
                print(f"Secure Chat Server running on port {port}. Press Ctrl+C to stop.")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
                finally:
                    srv.stop()
            else:
                print("Failed to start server. Invalid port or system error.")
        except ValueError:
            print("Invalid port argument.")