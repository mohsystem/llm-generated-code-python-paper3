import socket
import threading
import select
import time

class ServerControlPy:
    def __init__(self, sock, thread, stop_event):
        self._sock = sock
        self._thread = thread
        self._stop = stop_event
        self.port = sock.getsockname()[1]

    def stop(self):
        self._stop.set()
        # Wake up select by connecting
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                pass
        except Exception:
            pass
        self._thread.join()
        try:
            self._sock.close()
        except Exception:
            pass

def start_echo_server(port: int) -> ServerControlPy:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(128)
    stop_event = threading.Event()

    def run():
        try:
            while not stop_event.is_set():
                rlist, _, _ = select.select([s], [], [], 0.5)
                if not rlist:
                    continue
                try:
                    conn, _ = s.accept()
                except OSError:
                    break
                with conn:
                    conn.settimeout(3.0)
                    try:
                        while True:
                            data = conn.recv(4096)
                            if not data:
                                break
                            conn.sendall(data)
                    except Exception:
                        pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    # Ensure server thread started
    time.sleep(0.05)
    return ServerControlPy(s, t, stop_event)

def echo_once(host: str, port: int, message: str) -> str:
    data = message.encode("utf-8")
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(data)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        chunks = []
        while True:
            part = s.recv(4096)
            if not part:
                break
            chunks.append(part)
    return b"".join(chunks).decode("utf-8", errors="strict")

if __name__ == "__main__":
    server = start_echo_server(0)
    port = server.port
    tests = [
        "hello",
        "world",
        "こんにちは",
        "1234567890",
        "echo test with spaces",
    ]
    for msg in tests:
        echoed = echo_once("127.0.0.1", port, msg)
        print("Sent:   ", msg)
        print("Echoed: ", echoed)
        print("Match:  ", msg == echoed)
        print("---")
    server.stop()