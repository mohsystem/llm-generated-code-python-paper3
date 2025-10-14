import socket
import threading
import time


class EchoServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0, max_clients: int = 16):
        if not host:
            raise ValueError("Invalid host")
        if port < 0 or port > 65535:
            raise ValueError("Invalid port")
        if max_clients <= 0 or max_clients > 1024:
            raise ValueError("Invalid max_clients")
        self.host = host
        self.max_clients = max_clients
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self._srv.listen(50)
        self._srv.settimeout(1.0)
        self._running = threading.Event()
        self._accept_thread = threading.Thread(target=self._accept_loop, name="PyEchoServer", daemon=True)
        self._client_sema = threading.Semaphore(self.max_clients)

    @property
    def port(self) -> int:
        return self._srv.getsockname()[1]

    def start(self) -> None:
        self._running.set()
        self._accept_thread.start()

    def stop(self) -> None:
        self._running.clear()
        try:
            self._srv.close()
        except Exception:
            pass
        self._accept_thread.join(timeout=3.0)

    def _accept_loop(self):
        while self._running.is_set():
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._client_sema.acquire(timeout=0.1):
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            t.start()

    def _handle_client(self, conn: socket.socket):
        MAX_LEN = 8192
        try:
            conn.settimeout(5.0)
            buf = bytearray()
            while len(buf) < MAX_LEN:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                nl = chunk.find(b'\n')
                if nl != -1:
                    buf.extend(chunk[:nl])
                    break
                else:
                    buf.extend(chunk)
            if len(buf) > MAX_LEN:
                buf = buf[:MAX_LEN]
            conn.sendall(bytes(buf))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self._client_sema.release()


def echo_client(host: str, port: int, message: str) -> str:
    if not host:
        raise ValueError("Invalid host")
    if port <= 0 or port > 65535:
        raise ValueError("Invalid port")
    if message is None:
        message = ""
    data = message.encode("utf-8")
    if len(data) > 8192:
        data = data[:8192]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((host, port))
        s.sendall(data + b"\n")
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(c) for c in chunks) > 8192:
                    break
            except socket.timeout:
                break
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    server = EchoServer(port=0, max_clients=16)
    server.start()
    p = server.port
    tests = [
        "hello",
        "test message",
        "",
        "A" * 100,
        "Line1\\nLine2 with symbols !@#$%^&*()_+"
    ]
    for i, m in enumerate(tests, 1):
        resp = echo_client("127.0.0.1", p, m)
        print(f"Case {i}: {resp}")
    server.stop()