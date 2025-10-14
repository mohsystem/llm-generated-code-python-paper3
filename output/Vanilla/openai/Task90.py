import socket
import threading
import time

class Task90:
    class ChatServer:
        def __init__(self, port: int):
            self.port = port
            self.server_sock = None
            self.running = False
            self.clients = set()
            self.clients_lock = threading.Lock()
            self.accept_thread = None

        def start(self) -> bool:
            try:
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_sock.bind(("0.0.0.0", self.port))
                self.server_sock.listen(100)
                self.running = True
                self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
                self.accept_thread.start()
                return True
            except Exception as e:
                print("Start error:", e)
                return False

        def stop(self):
            self.running = False
            try:
                if self.server_sock:
                    self.server_sock.close()
            except:
                pass
            with self.clients_lock:
                for c in list(self.clients):
                    try:
                        c.close()
                    except:
                        pass
                self.clients.clear()
            if self.accept_thread:
                self.accept_thread.join(timeout=1.0)

        def _accept_loop(self):
            next_id = 1
            while self.running:
                try:
                    client_sock, addr = self.server_sock.accept()
                except OSError:
                    break
                name = f"Client-{next_id}"
                next_id += 1
                with self.clients_lock:
                    self.clients.add(client_sock)
                threading.Thread(target=self._handle_client, args=(client_sock, name), daemon=True).start()
                self._send(client_sock, f"Welcome {name}\n")

        def _handle_client(self, client_sock: socket.socket, name: str):
            try:
                client_sock.settimeout(0.5)
                buf = b""
                while self.running:
                    try:
                        data = client_sock.recv(4096)
                        if not data:
                            break
                        buf += data
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            msg = f"{name}: {line.decode('utf-8', 'ignore')}\n"
                            self.broadcast(msg)
                    except socket.timeout:
                        continue
            except:
                pass
            finally:
                with self.clients_lock:
                    if client_sock in self.clients:
                        self.clients.remove(client_sock)
                try:
                    client_sock.close()
                except:
                    pass

        def _send(self, sock, msg: str):
            try:
                sock.sendall(msg.encode("utf-8"))
            except:
                pass

        def broadcast(self, message: str):
            with self.clients_lock:
                for c in list(self.clients):
                    try:
                        c.sendall(message.encode("utf-8"))
                    except:
                        try:
                            c.close()
                        except:
                            pass
                        self.clients.discard(c)

    @staticmethod
    def start_server(port: int):
        srv = Task90.ChatServer(port)
        if srv.start():
            return srv
        return None

if __name__ == "__main__":
    port = 50591
    server = Task90.start_server(port)
    if not server:
        print("Failed to start server")
        raise SystemExit(1)

    def client_sim(name, msg, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect(("127.0.0.1", port))
            # read welcome
            try:
                print(name, "recv:", s.recv(4096).decode("utf-8").strip())
            except:
                pass
            s.sendall((msg + "\n").encode("utf-8"))
            end = time.time() + 0.6
            s.settimeout(0.2)
            while time.time() < end:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    print(name, "recv:", data.decode("utf-8").strip())
                except socket.timeout:
                    break
            s.close()
        except Exception as e:
            print(name, "error:", e)

    threads = []
    for i in range(1, 6):
        t = threading.Thread(target=client_sim, args=(f"TClient-{i}", f"Hello from TClient-{i}", port))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    server.stop()
    print("Server stopped.")