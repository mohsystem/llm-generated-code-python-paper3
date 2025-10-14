import socket
import threading
from typing import Optional, Tuple, List

MAX_MESSAGE_BYTES = 4096
SOCKET_TIMEOUT_SEC = 5.0
BACKLOG = 50

class ServerHandle:
    def __init__(self, sock: socket.socket, thread: threading.Thread, running_flag: threading.Event, port: int):
        self.sock = sock
        self.thread = thread
        self.running_flag = running_flag
        self.port = port

def _read_line_limited(conn: socket.socket, max_bytes: int) -> Optional[bytes]:
    conn.settimeout(SOCKET_TIMEOUT_SEC)
    data = bytearray()
    while len(data) < max_bytes:
        try:
            chunk = conn.recv(1)
        except socket.timeout:
            return None
        if not chunk:
            if len(data) == 0:
                return None
            break
        b = chunk[0]
        if b == 10:  # '\n'
            break
        if b == 13:  # '\r' (tolerate CRLF)
            continue
        data.append(b)
    return bytes(data)

def _handle_client(client_sock: socket.socket) -> None:
    with client_sock:
        client_sock.settimeout(SOCKET_TIMEOUT_SEC)
        while True:
            line = _read_line_limited(client_sock, MAX_MESSAGE_BYTES)
            if line is None:
                break
            if len(line) > MAX_MESSAGE_BYTES:
                break
            try:
                client_sock.sendall(line + b'\n')
            except (socket.timeout, OSError):
                break

def start_echo_server(port: int) -> ServerHandle:
    if not (0 <= port <= 65535):
        raise ValueError("Port out of range")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(BACKLOG)
    assigned_port = srv.getsockname()[1]
    running = threading.Event()
    running.set()

    def accept_loop() -> None:
        while running.is_set():
            try:
                client, _ = srv.accept()
                t = threading.Thread(target=_handle_client, args=(client,), daemon=True)
                t.start()
            except OSError:
                if running.is_set():
                    continue
                break

    t = threading.Thread(target=accept_loop, name="EchoServer-Accept", daemon=True)
    t.start()
    return ServerHandle(srv, t, running, assigned_port)

def stop_echo_server(handle: ServerHandle) -> None:
    if handle is None:
        return
    handle.running_flag.clear()
    try:
        handle.sock.close()
    except OSError:
        pass
    handle.thread.join(timeout=2.0)

def send_echo(host: str, port: int, message: str) -> str:
    if not host or not isinstance(host, str):
        raise ValueError("Host required")
    if not (1 <= port <= 65535):
        raise ValueError("Port out of range")
    data = message.encode("utf-8") if message is not None else b""
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError("Message too long")
    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_SEC) as s:
        s.settimeout(SOCKET_TIMEOUT_SEC)
        s.sendall(data + b"\n")
        resp = bytearray()
        while len(resp) < MAX_MESSAGE_BYTES:
            try:
                ch = s.recv(1)
            except socket.timeout:
                break
            if not ch:
                break
            if ch == b"\n":
                break
            if ch == b"\r":
                continue
            resp.extend(ch)
        return resp.decode("utf-8", errors="strict")

if __name__ == "__main__":
    handle = None
    try:
        handle = start_echo_server(0)
        port = handle.port
        tests: List[str] = [
            "Hello, world!",
            "",
            "The quick brown fox jumps over 13 lazy dogs.",
            "Symbols: !@#$%^&*()_+-=[]{}|;:',.<>/?",
            "One more test line"
        ]
        for t in tests:
            r = send_echo("127.0.0.1", port, t)
            print(f"Sent: [{t}] | Echoed: [{r}]")
    finally:
        stop_echo_server(handle)